# ---------------------------------------------------------------------------
# $Id$
# 
# This module encapsulates functionality around using PEARL encrypted tokens.
# It can generate tokens from input data, output PII from tokens, output RMC
# tokens from tokens or standardize all input tokens to a single RMC token id.
#
# ---------------------------------------------------------------------------

package ARC::PEARL::Tokenizer;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
our @EXPORT = qw(tok_init tokenize_strings detokenize);
our @EXPORT_OK = qw(tok_get_output_map_id tok_get_layout
      tok_tokenize_xo tok_detokenize_xo tok_tokenize_aric tok_detokenize_aric retokenize_aric
      encrypt_rmc decrypt_rmc encrypt_do decrypt_do
      encrypt_xo decrypt_xo 
);

use strict;
use warnings;
use Crypt::CBC;
#use Digest;
#use Digest::MD5 qw(md5_hex);
#use Digest::SHA qw(sha512_hex);
#use List::Util 'shuffle';
use Data::Dumper;
use ARC::Common qw(dbg list_minus);

# prototypes
sub add_noise($);
sub add_rmc_map($);
sub build_rmc_map();
sub minlen_rmc_map_id();
sub tok_init(%);
sub tokenize_strings($$);
sub detokenize($);
sub tok_tokenize_aric($$$);
sub encrypt_rmc($$);
sub decrypt_rmc($$);
sub encrypt_xo($);
sub decrypt_xo($);
sub encrypt_do($);
sub decrypt_do($);
#
sub tok_aric_str_to_array($);
sub tok_get_output_map_id();
sub tok_get_layout();
sub tok_detokenize_xo($;$);
sub retokenize_aric($$$);

# obsolete
sub random_str($@);
sub generate_map_table($$);

# globals
my %opts = ();
my %rmc_map = ();
my %rmc_rmap = ();
my %layout_codes_to_pos = ();
my @layout_fields = ();
my $output_map_id = '';
my $xo_cipher;
my $do_cipher;
my $E = "Tokenizer ERROR";
my $W = "Tokenizer WARNING";

our $VERSION = 0.1;



# ---------------------------------------------------------------------------
# Initialize the tokenizer
# ---------------------------------------------------------------------------
sub tok_init(%) {
   my ($href) = @_;
   dbg(2, "Tokenizer init...\n");

   # document the options we expect and set defaults
   my %defaults = (
      'delimiter'       => '|', 
      'output-aric'     => 0,
      'output-pii'      => 0,
      'aric-map-id'     => '',
      'encrypt-do'      => 0,
      'seperate-do'     => 0,
      'xo-do-delimiter' => 'h',
      'layout'          => [qw(fn:fname ln:lname ss:ssn do:dobymd)],
      'keys' => {
         'xo_version'               => undef,
         'xo_cipher_alog'           => 'Rijndael',
         'xo_cipher_key'            => undef,
         'xo_cipher_salt'           => undef,
         'do_cipher_alog'           => 'Rijndael',
         'do_cipher_key'            => undef,
         'aric_token_delimiter'     => '|',
         'aric_header_delimiter'    => ':',
         'rmc_salt'                 => undef,
         'rmc_input_domain'         => undef,
         'rmc_max_char_map_length'  => 4,
         'iv'                       => undef,
      },
   );

   # override defaults with input parms
   %opts = (%defaults, %$href);
   %{$opts{keys}} = (%{$defaults{keys}}, %{$href->{keys}});
   dbg(4, "Tokenizer opts:\n".Dumper(\%opts)."\n");

   # check for required keys
   my @required_keys = qw(
         xo_version xo_cipher_algo xo_cipher_key xo_cipher_salt
         do_cipher_algo
         aric_cipher
      );
   my @missing_keys = list_minus(\@required_keys, [keys $opts{keys}]);
   if ( (scalar @missing_keys) > 0 ) {
      die("$E: key file is missing required keys: " . join(', ', @missing_keys) . "\n");
   }

   # each token version may have different options. Set those here
   dbg(2, "setting token version specific options\n", 2);
   if ( $opts{keys}{xo_version} == 1 ) {
      die("$E: key file aric_cipher is wrong for this token version!\n") if ( lc($opts{keys}{aric_cipher}) ne 'rmc' );
      die("$E: rmc_salt is not defined in the key file!\n") if ( ! defined($opts{keys}{rmc_salt}) );
      $opts{keys}{aric_header_delimiter} = ':';
      $opts{keys}{aric_token_delimiter} = '|';
   }
   else {
      die("$E: unknown xo_version\n");
   }

   # default to all 7-bit ASCII printable characters 
   # see http://perldoc.perl.org/perlrecharclass.html#POSIX-Character-Classes
   unless( defined($opts{keys}{rmc_input_domain}) ) {
      foreach my $chr ( map {chr} (0..127) ) {
         #next if ( $chr =~ /[|\\]/ );  # exclude a few problematic characters
         #push(@input_domain, $chr) if $chr =~ m/\p{XPosixPrint}/; # full range unicode (will work for > 127)
         #push(@input_domain, $chr) if $chr =~ m/[[:print:]]/;    # ascii range
         $opts{keys}{rmc_input_domain} .= $chr if $chr =~ m/[[:print:]]/;    # ascii range
      }
   }
   dbg(4, length($opts{keys}{rmc_input_domain}) . " characters in the input domain:\n", 4);
   dbg(4, "input domain:--->" . $opts{keys}{rmc_input_domain} . "<---\n", 4);

   # build the in-memory rmc maps
   build_rmc_maps();

   # pregenerate the token header
   #
   # token header format = VVS*D
   # where:
   #   VV   = arci version number in hex
   #   S*   = variable length string, map table key (substr of password hash)
   #   D    = token header delimiter
   # 
   # NOTE: what follows aric version in the header, should be version dependent. For
   #   now this is unimplemented.
   #
   $opts{keys}{xo_header} = sprintf("%02X", $opts{keys}{xo_version}).$output_map_id.$opts{keys}{aric_header_delimiter};
   dbg(4, "XO header: ".$opts{keys}{xo_header}."\n", 2);

   # initialize the XO/DO encryption objects
   dbg(2, "initializing encryption ciphers\n", 2);

   # generate a 16 byte Initialization Vector from "salt"
   $opts{'keys'}{'iv'} = substr(Digest::MD5::md5_hex($opts{keys}{xo_cipher_salt}), 0, 16)
      unless( $opts{'keys'}{'iv'} );

   # generate the XO encryption cipher object
   $xo_cipher = Crypt::CBC->new(
      -key           => $opts{keys}{xo_cipher_key},
      -literal_key   => 0,  # treat -key as a passphrase, not the literal encryption key
      -cipher        => $opts{keys}{xo_cipher_algo},
      #-salt          => $cipher_salt,
      #-iv            => $opts{keys}{cipher_salt},
      -iv            => $opts{keys}{iv},
      -header        => 'none',
   );

   if ( $opts{keys}{do_cipher_key} ) {
      $do_cipher = Crypt::CBC->new(
         -key           => $opts{keys}{do_cipher_key},
         -literal_key   => 0,  # treat -key as a passphrase, not the literal encryption key
         -cipher        => $opts{keys}{do_cipher_algo},
         #-salt          => $cipher_salt,
         #-iv            => $opts{keys}{cipher_salt},
         #-iv            => $opts{keys}{iv},
         #-header        => 'none',
      );
   }

   # create the layout: a hash of field_code => output_position
   # and array of output field names
   my $i = 0;
   foreach my $field ( @{$opts{layout}} ) {
      my ($code, $name) = split(':', $field);
      $layout_codes_to_pos{$code} = $i++;
      push(@layout_fields, $name);
   }
}


# ---------------------------------------------------------------------------
# tokenzie every string in the array
#
#  strs_ref       : array ref of strings
#  flds_ref       : array ref of field names
#
# OJO: we could generate map_id here for greater randomness
# ---------------------------------------------------------------------------
sub tokenize_strings($$) {
   my ($strs_ref, $flds_ref) = @_;

   # generate aric tokens (currently using RMC)
   #my @arr = map { encrypt_rmc($_, $map_id); } @$strs_ref;
   my @arr = ();
   for (my $i = 0; $i < scalar @$strs_ref; $i++ ) {
      push(@arr, tok_tokenize_aric($strs_ref->[$i], $output_map_id, substr($flds_ref->[$i],0,2)));
   }
   if ( $opts{'output-aric'} ) { return @arr; }

   # concatenate all aric tokens
   my $aric = join($opts{keys}{aric_token_delimiter}, @arr);

   # aric will now put on the XO armor (see init_tokenizer() for info on xo_header)
   my $xo = $opts{keys}{xo_header} . encrypt_xo($aric);

   # generate the DO token and return
   if ( $opts{'seperate-do'} ) {
      return ($xo, encrypt_do(join($opts{delimiter}, @$strs_ref)));
   }

   return ($xo . $opts{'xo-do-delimiter'} . encrypt_do(join($opts{delimiter}, @$strs_ref)));
}

# ---------------------------------------------------------------------------
# OJO: I don't like this function. It has too many possible outputs. It's too
# generic and unclear what it's purpose is. Need to rethink.
#
# decrypt/unwrap the token back to the requested state (aric, pii, etc)
# Always returns an array of pii or aric tokens
#
# See tokenize_strings() for token header notes
# ---------------------------------------------------------------------------
sub detokenize($) {
   my ($token) = @_;

   # pull header from token and parse out it's two values
   my ($hdr, $tok) = split(quotemeta($opts{keys}{aric_header_delimiter}), $token);
   my $map_version = hex(substr($hdr,0,2));  # first two bytes, in hex
   my $map_id      = substr($hdr,2); # map key

   if ( $map_version != $opts{keys}{xo_version} ) {
      die("$E: Unable to decrypt token: xo_version missmatch.\n"
         ."    key file xo_version = " . $opts{keys}{xo_version} 
         . ", token xo_version = $map_version\n");
   }

   # seperate xo and do tokens
   my ($xo, $do) = split($opts{'xo-do-delimiter'}, $tok);

   # aric will now take off the XO armor
   my $aric = decrypt_xo($xo);

   if ( $opts{'output-aric'} ) {
      # retokenize
      if ( ! $opts{'aric-map-id'} || $map_id eq $opts{'aric-map-id'} ) {
         # no need, already in the requested map_id
         return split(quotemeta($opts{keys}{aric_token_delimiter}), $aric);
      }
      my @aric = split(quotemeta($opts{keys}{aric_token_delimiter}), $aric);
      my @ret = ();
      foreach my $tkn ( @aric ) {
         my ($fld, $t) = split(quotemeta($opts{keys}{aric_header_delimiter}), $tkn);
         push(@ret, tok_tokenize_aric(decrypt_rmc($tkn, $map_id), $output_map_id, $fld));
      }
      return @ret;
   } else {
      return split(quotemeta($opts{keys}{aric_token_delimiter}), $aric);
   }

   # decrypt aric tokens back to plaintext
   if ( $opts{'output-pii'} ) {
      return map { decrypt_rmc($_, $map_id); } split(quotemeta($opts{keys}{aric_token_delimiter}), $aric);
   }

   # should never get here
   die("$E: detokenize(): invalid set of options");
}

# ---------------------------------------------------------------------------
# return the output_map_id as defined during init()
# ---------------------------------------------------------------------------
sub tok_get_output_map_id() {
   return $output_map_id;
}

# ---------------------------------------------------------------------------
# return the output layout
# ---------------------------------------------------------------------------
sub tok_get_layout() {
   return @layout_fields;
}

# ---------------------------------------------------------------------------
# split an aric token string into an array of aric tokens, in the output layout order
#
# $_[0]  = aric token string (what comes out of decrypt_xo()
# ---------------------------------------------------------------------------
sub aric_token_str_to_array($) {
   my @ret = ();

   foreach ( split(quotemeta($opts{keys}{aric_token_delimiter}), $_[0]) ) {
      my ($code, $tok) = split(quotemeta($opts{keys}{aric_header_delimiter}), $_);
      $ret[$layout_codes_to_pos{$code}] = $tok;
   }
   return @ret;
}

# ---------------------------------------------------------------------------
# re-encrypt aric token from map_id to new_map_id
#
# $_[0]  = aric token
# $_[1]  = from_map_id
# $_[2]  = to_map_id
# ---------------------------------------------------------------------------
sub retokenize_aric($$$) {
   return encrypt_rmc(decrypt_rmc($_, $_[1]), $_[2]);
}

# ---------------------------------------------------------------------------
# decrypt/unwrap the XO token back to the ARIC tokens
#
# $_[0]  = xo token
# $_[1]  = true|FALSE (optional) if true, do not reformat into init() defined layout
#
# ! ! ! NOTE: ! ! ! !
# By default, tokens are STRIPPED of their field name codes and reordered into the
# output layout order. IF $_[1] is TRUE, then the field name codes are left on the
# tokens, and they are returned in their existing order. 
#
# SO, if $_[1] is FALSE, what you get back is:
#
#  (c0c8c8a6c009c0c0,a6c8966f09c009966f,e14d4fb3,d67b893e)
#
# BUT, if $_[1] is TRUE, what you get back is:
#
#  (c0c8c8a6c009c0c0,a6c8966f09c009966f,e14d4fb3,d67b893e)
#
# Not a great interface... but my justification is better performance. Need to
# profile to see if it's worth it.
# ---------------------------------------------------------------------------
sub tok_detokenize_xo($;$) {

   # pull header from token and parse out it's two values
   my ($hdr, $tok) = split(quotemeta($opts{keys}{aric_header_delimiter}), $_[0]);
   my $map_version = hex(substr($hdr,0,2));  # first two bytes, in hex
   my $map_id      = substr($hdr,2); # map key

   if ( $map_version != $opts{keys}{xo_version} ) {
      die("$E: Unable to decrypt token: xo_version missmatch.\n"
         ."    key file xo_version = " . $opts{keys}{xo_version} 
         . ", token xo_version = $map_version\n");
   }

   # disentangle xo and do tokens
   my ($xo, $do) = split($opts{'xo-do-delimiter'}, $tok);

   # aric will now take off the XO armor
   #my $aric = decrypt_xo($xo);

   if ( $_[1] ) {  # if $dump_aric - just dump the tokens
      return (($map_version, $map_id), split(quotemeta($opts{keys}{aric_token_delimiter}), decrypt_xo($xo)));
   }
   return (($map_version, $map_id), aric_token_str_to_array(decrypt_xo($xo)));
}

# ---------------------------------------------------------------------------
# create ARIC token
#
# $_[0]  = plaintext
# $_[1]  = map_id
# $_[2]  = field code (fn for fname, etc)
# ---------------------------------------------------------------------------
sub tok_tokenize_aric($$$) {
   #my ($plaintext, $map_id, $fieldcode) = @_;

   # token header format = FF:
   # where:
   #   FF   = field name code
   # NOTE: output-aric is for debugging, so the map_id is included
   if ( $opts{'output-aric'} ) {
      # OJO: ! ! ! This need to go away - should only have one style rmc token
      return $_[2] . $_[1] . $opts{keys}{aric_header_delimiter} . encrypt_rmc($_[0], $_[1]);
   } else {
      return $_[2] . $opts{keys}{aric_header_delimiter} . encrypt_rmc($_[0], $_[1]);
   }
}

# ---------------------------------------------------------------------------
# create RMC (Random Map Cipher) token
#
# NOTE: $map_id can also be generated here rather than init() for more randomness
#
# $_[0]  = plaintext
# $_[1]  = map_id
# ---------------------------------------------------------------------------
sub encrypt_rmc($$) {
   #my ($plaintext, $map_id) = @_;
   my $token = '';

   add_rmc_map($_[1]) unless ( $rmc_map{$_[1]} );

   # character by character, replace original with mapped value from map_id row
   foreach my $c ( split('', uc($_[0])) ) {
      # TODO: Need to print the record this is from to log file and warn that character $c was dropped
      $token .= $rmc_map{$_[1]}{$c} || '';  # drop character if not found in map
   }

   return $token;
}

# ---------------------------------------------------------------------------
# Unencrypt ARIC token
#
# $_[0]  = token
# $_[1]  = map_id
# ---------------------------------------------------------------------------
sub tok_detokenize_aric($$) {
   # pull field name header from token 
   my ($fld, $tok) = split(quotemeta($opts{keys}{aric_header_delimiter}), $_[0]);
   return ($fld, (decrypt_rmc($tok, $_[1])));
}



# ---------------------------------------------------------------------------
# unencrypt RMC token (Random Map Cipher)
# 
# $_[0]  = token
# $_[1]  = map_id
# ---------------------------------------------------------------------------
sub decrypt_rmc($$) {
   #my ($token, $map_id) = @_;

   add_rmc_map($_[1]) unless ( $rmc_map{$_[1]} );

   # length of rmc map id is the length strings it maps to or from
   # chunk up the string into equal parts of $len lengh, and decode each
   my $len = length($_[1]);

   # surprisingly, this does not profile any faster
   #return join("", map {$rmc_rmap{$_[1]}{$_}} unpack("(a$len)*", $_[0]));

   # chunk the string into equal parts of $len length
   my $plaintext = "";
   foreach my $chunk ( unpack("(a$len)*", $_[0]) ) {
      $plaintext .= $rmc_rmap{$_[1]}{"$chunk"}; 
   }
   return $plaintext;

}



# ---------------------------------------------------------------------------
# create XO (eXecution Owner) token 
# $_[0]     = plaintext
# ---------------------------------------------------------------------------
sub encrypt_xo($) {
   return $xo_cipher->encrypt_hex($_[0]);
}


# ---------------------------------------------------------------------------
# decrypt XO (eXecution Owner) token 
# $_[0]     = ciphertext
# ---------------------------------------------------------------------------
sub decrypt_xo($) {
   return $xo_cipher->decrypt_hex($_[0]);
}

# ---------------------------------------------------------------------------
# create DO (Data Owner) token 
# $_[0]     = plaintext
# ---------------------------------------------------------------------------
sub encrypt_do($) {
   return $do_cipher->encrypt_hex($_[0]);
}


# ---------------------------------------------------------------------------
# decrypt DO (Data Owner) token 
# $_[0]     = ciphertext
# ---------------------------------------------------------------------------
sub decrypt_do($) {
   return $do_cipher->decrypt_hex($_[0]);
}


# ---------------------------------------------------------------------------
# Add more bytes to the noise map
# ---------------------------------------------------------------------------
sub add_noise($) {
   return Digest::SHA::sha512_hex($_[0]);
}

# ---------------------------------------------------------------------------
# Generate the map and reverse map for a given map_id, and add them to the map
# tables. The map is a HoH data structure where: 
#  map_id => {
#     input_domain character => map string (n bytes long)   # for maps
#     OR
#     map string (n bytes long) => input domain character   # for reverse maps
#  }
# ---------------------------------------------------------------------------
sub add_rmc_map($) {
   my ($map_id) = @_;
   dbg(2, "generating rmc map for $map_id\n", 4);
   if ( $rmc_map{$map_id} ) {
      dbg(2, "rmc map for $map_id already exists, skipping...\n", 2);
      return;
   }

   my $len = length($map_id);
   if ( $len < minlen_rmc_map_id() ) {
      die("$E: unable to represent all intput domain characters with the\n"
        . "current output domain, using map_id of length $len\n");
   }

   # generate bytes of predictable noise for this map_id
   my $map_noise = add_noise($map_id . $opts{keys}{rmc_salt});
   dbg(5, "adding noise: map_noise[$map_id] (" . length($map_noise) . " bytes): $map_noise\n", 6);

   my $i = 0;
   foreach my $c ( split('', $opts{keys}{rmc_input_domain}) ) {
      $map_noise .= add_noise($map_noise) if ( $i + $len > length($map_noise) );
      my $str = substr($map_noise, $i++, $len);
      until ( ! exists($rmc_rmap{$map_id}{$str}) ) {
         $map_noise .= add_noise($map_noise) if ( $i + $len > length($map_noise) );
         $str = substr($map_noise, $i++, $len) 
      }
      $rmc_rmap{$map_id}{$str} = $c;
      $rmc_map{$map_id}{$c} = $str;
   }
   dbg(4, "max map_noise index used = " . ($i + $len) . " out of " . length($map_noise) . "\n", 6);
   dbg(5, "rmc_map{$map_id}:\n".Dumper($rmc_map{$map_id})."\n");
   dbg(5, "rmc_rmap{$map_id}:\n".Dumper($rmc_rmap{$map_id})."\n");
}

# ---------------------------------------------------------------------------
# Build the in-memory random map dictionary
#
# Currently we generate one map for each $len. We could however, generate
# multiple maps for each $len, which would give us much greater "randomness".
# ---------------------------------------------------------------------------
sub build_rmc_maps() {
   dbg(2, "generating rmc maps\n", 2);
 
   if ( $opts{'aric-map-id'} ) {
      # we have been asked to build a specific map
      add_rmc_map($opts{'aric-map-id'});
      $output_map_id = $opts{'aric-map-id'};
   }
   elsif ( $opts{'encrypt-do'} ) {
      # DO does not trust XO, generate random maps based on DO password
      my $pw_hash = Digest::MD5::md5_hex($opts{keys}{do_cipher_key});

      # generate a series of maps
      my $min_strlen = minlen_rmc_map_id();
      my $max_strlen = int($opts{keys}{rmc_max_char_map_length});
      foreach my $len ($min_strlen .. $max_strlen) {
         dbg(3, "building rmc map for len $len\n", 4);
         add_rmc_map(substr($pw_hash, 0, $len));
      }

      # pick a random map_id to use
      my @keys = keys %rmc_map;
      $output_map_id = $keys[int(rand(scalar @keys))];
   }
   else {
      # default is to use XO password, and minimum length
      my $pw_hash = Digest::MD5::md5_hex($opts{keys}{xo_cipher_key});
      $output_map_id = substr($pw_hash, 0, minlen_rmc_map_id());
      add_rmc_map($output_map_id);
   }

   dbg(2, "output map_id selected for this run: ".$output_map_id."\n", 2);
   dbg(5, "rmc_map:\n".Dumper(\%rmc_map)."\n");
   dbg(5, "rmc_rmap:\n".Dumper(\%rmc_rmap)."\n");
}

# ---------------------------------------------------------------------------
# Greg's input here! What is the minimum string length of output domain
# characters that we need to represent every character in the input domain.
#
# Note: we assume output domain is hex (16 distinct characters)
# ---------------------------------------------------------------------------
sub minlen_rmc_map_id() {
   return POSIX::ceil(log(length($opts{keys}{rmc_input_domain}))/log(16));
}

# ---------------------------------------------------------------------------
# Geneate a random string from the passed in domain of characters
# ---------------------------------------------------------------------------
sub random_str($@) {
   my ($len, @domain) = @_;

   my $str;
   for (0 .. $len - 1) {
      $str .= $domain[int(rand(scalar(@domain)))];
   }
   return $str;
}



# ---------------------------------------------------------------------------
# Geneate a random map table
#
# NOTE:
#   This is a convenience function to quickly generate random map tables.
# ---------------------------------------------------------------------------
sub generate_map_table($$) {
   my ($num_rows, $max_strlen) = @_;

   my @output_domain = split('','abcdef0123456789'); # valid hexadecimal chars
   # input domain is the list of all ASCII printable characters 
   # see http://perldoc.perl.org/perlrecharclass.html#POSIX-Character-Classes
   my @input_domain = ();
   foreach my $chr ( map {chr} (0..127) ) {
      next if ( $chr =~ /[|\\]/ );
      push(@input_domain, $chr) if $chr =~ m/[[:print:]]/;    # ascii range unicode
      #push(@input_domain, $chr) if $chr =~ m/\p{XPosixPrint}/; # full range unicode
   }
   #foreach my $chr ( @input_domain ) {print "CHR: $chr, ORD: " . ord($chr) . "\n";}

   # Greg's input here!
   # what is the minimum string length of output characters we need to represent
   # every character in the input domain.
   my $min_strlen = POSIX::ceil(log(scalar(@input_domain))/log(scalar(@output_domain)));
   if ( $max_strlen < $min_strlen ) {
      die("$E: unable to represent all intput domain characters with the\n"
        . "current output domain, using a max length of $max_strlen\n");
   }

   # print the reference, map type 0 (a=a) row
   print '0|' . join('|',@input_domain) . "\n";

   # generate a random mapping of characters for each char in the @input_domain array
   #  - the entire row will have the same len
   #  - make sure each string in the row is unique for that row
   my %row = ();
   for my $i ( 1 .. $num_rows ) {
      my $len = $min_strlen + int(rand($max_strlen - $min_strlen + 1));
      foreach my $col ( @input_domain ) {
         my $str = random_str($len, @output_domain);
         $str = random_str($len, @output_domain) until ( ! exists($row{$str}) );
         $row{$str} = 1;
      }
      print $i . '|' . join("|", keys %row) . "\n";
      %row = ();
   }
}



1;
