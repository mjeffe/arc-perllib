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
# export functions
our @EXPORT = qw(init_tokenizer tokenize_strings detokenize_strings);
our @EXPORT_OK = qw(tok_encrypt_rmc tok_decrypt_rmc tok_encrypt_xo tok_decrypt_xo tok_encrypt_do tok_decrypt_do);

use strict;
use warnings;
use Crypt::CBC;
#use Digest;
#use Digest::MD5 qw(md5_hex);
#use Digest::SHA qw(sha512_hex);
use List::Util 'shuffle';
use Data::Dumper;
use ARC::Common;
use ARC::Common qw($E $W);

# prototypes
sub add_noise($);
sub build_rmc_map();
sub tok_encrypt_rmc($$$);
sub tok_decrypt_rmc($);
sub tok_encrypt_xo($);
sub tok_decrypt_xo($);
sub tok_encrypt_do($);
sub tok_decrypt_do($);
# exportable
sub init_tokenizer(%);
sub tokenize_strings($$);
sub detokenize_strings($);
# obsolete
sub random_str($@);
sub generate_map_table($$);

# globals
my %opts = ();
my %rmc_map = ();
my %rmc_rmap = ();
my $map_id = '';




# ---------------------------------------------------------------------------
# Initialize the tokenizer
# ---------------------------------------------------------------------------
sub init_tokenizer(%) {
   my ($href) = @_;
   #%opts = %$href;
   #$opts{'xo-do-delimiter'} = 'h';

   # document the options we expect and set defaults
   my %defaults = (
      'delimiter'       => '|', 
      'output-aric'     => 0,
      'seperate-do'     => 0,
      'xo-do-delimiter' => 'h',
      'keys' => {
         'ptk_version'              => undef,
         'aric_version'             => undef,
         'aric_token_delimiter'     => '|',
         'aric_header_delimiter'    => ':',
         'rmc_salt'                 => undef,
         'rmc_input_domain'         => undef,
         'rmc_max_char_map_length'  => 4,
         'xo_cipher_alog'           => 'Rijndael',
         'xo_cipher_key'            => undef,
         'xo_cipher_salt'           => undef,
         'do_cipher_alog'           => 'Rijndael',
         'do_cipher_key'            => undef,
         'iv'                       => undef,
      },
   );

   # override defaults with input parms
   %opts = (%defaults, %$href);
   %{$opts{keys}} = (%{$defaults{keys}}, %{$href->{keys}});
   # generate a 16 byte Initialization Vector from "salt"
   $opts{'keys'}{'iv'} = substr(Digest::MD5::md5_hex($opts{keys}{xo_cipher_salt}), 0, 16)
      unless( $opts{'keys'}{'iv'} );
   #print "ARC::Tokenizer init opts:\n" . Dumper(\%opts) . "\n";

   # check for required options
   die("$E: aric_version is not defined in the key file!\n")
      unless( defined($opts{keys}{aric_version}) );
   die("$E: xo_cipher_key is not defined in the key file!\n")
      unless( defined($opts{keys}{xo_cipher_key}) );
   die("$E: xo_cipher_salt is not defined in the key file!\n")
      unless( defined($opts{keys}{xo_cipher_salt}) );

   # each version of rmc has different options. Set those here
   if ( $opts{keys}{aric_version} == 3 ) {
      die("$E: rmc_salt is not defined in the key file!\n") if ( ! defined($opts{keys}{rmc_salt}) );
      $opts{keys}{aric_header_delimiter} = ':';
      $opts{keys}{aric_token_delimiter} = '|';
   }
   else {
      die("$E: unknown aric_version\n");
   }

   # build the in-memory rmc maps
   build_rmc_map();

   # pick a random map key to use for this instantiation
   # This could also be done in tokenize_strings() for greater randomness
   my @keys = keys %rmc_map;
   $map_id = $keys[int(rand(scalar @keys))];
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
   #my @arr = map { tok_encrypt_rmc($_, $map_id); } @$strs_ref;
   my @arr = ();
   for (my $i = 0; $i < scalar @$strs_ref; $i++ ) {
      push(@arr, tok_encrypt_rmc($strs_ref->[$i], $map_id, substr($flds_ref->[$i],0,2)));
   }
   if ( $opts{'output-aric'} ) { return @arr; }

   # concatenate all aric tokens
   my $aric = join($opts{keys}{aric_token_delimiter}, @arr);

   # aric will now put on the XO armor
   #
   # token header format = VVS*:
   # where:
   #   VV   = arci version number in hex
   #   S*   = variable length string, map table key (substr of DO password hash)
   # 
   # NOTE: what follows aric version in the header, should be version dependent. For
   #   now this is unimplemented.
   #
   my $xo = sprintf("%02X", $opts{keys}{aric_version}) . $map_id . $opts{keys}{aric_header_delimiter} 
         . tok_encrypt_xo($aric);

   # generate the DO token
   if ( $opts{'seperate-do'} ) {
      return ($xo, tok_encrypt_do(join($opts{delimiter}, @$strs_ref)));
   }

   return ($xo . $opts{'xo-do-delimiter'} . tok_encrypt_do(join($opts{delimiter}, @$strs_ref)));
}

# ---------------------------------------------------------------------------
# detokenzie every string in the array ref
#
# See tokenize_strings() for token header notes
# ---------------------------------------------------------------------------
sub detokenize_strings($) {
   #my ($arrayref) = @_;
   my ($token) = @_;

   # pull header from token and parse out it's two values
   my ($hdr, $tok) = split(quotemeta($opts{keys}{aric_header_delimiter}), $token);
   my $map_version = hex(substr($hdr,0,2));  # first two bytes, in hex
   my $map_id      = substr($hdr,2); # map key

   if ( $map_version != $opts{keys}{aric_version} ) {
      die("$E: Unable to decrypt token: aric_version missmatch.\n"
         ."    key file aric_version = " . $opts{keys}{aric_version} 
         . ", token aric_version = $map_version\n");
   }

   # seperate xo and do tokens
   my ($xo, $do) = split($opts{'xo-do-delimiter'}, $tok);

   # aric will now take off the XO armor
   #my @arr = map { tok_decrypt_xo($_); } @$arrayref;
   my $aric = tok_decrypt_xo($xo);

   # parse out the aric tokens
   my @aric = split(quotemeta($opts{keys}{aric_token_delimiter}), $aric);
   return @aric;

   # decrypt aric tokens back to plaintext
   #my @plaintext = map { tok_decrypt_rmc($_); } @aric;

   #return @plaintext;
}


# ---------------------------------------------------------------------------
# create RMC (Random Map Cipher) token
# ---------------------------------------------------------------------------
sub tok_encrypt_rmc($$$) {
   my ($plaintext, $map_id, $fieldname) = @_;

   # $map_id can also be generated here rather than init() for more randomness

   # token header format = FF:
   # where:
   #   FF   = field name code
   my $token = $fieldname . $opts{keys}{aric_header_delimiter};
   # NOTE: output-aric is for debugging, so the map_id is included
   if ( $opts{'output-aric'} ) {
      $token = $fieldname . $map_id . $opts{keys}{aric_header_delimiter};
   }

   # character by character, replace original with mapped value from map_id row
   foreach my $c ( split('', uc($plaintext)) ) {
      # TODO: Need to print the record this is from to log file and warn that character $c was dropped
      $token .= $rmc_map{$map_id}{$c} || '';  # drop character if not found in map
   }

   return $token;
}


# ---------------------------------------------------------------------------
# unencrypt RMC token (Random Map Cipher)
# 
# See tok_encrypt_rmc() for more notes
# ---------------------------------------------------------------------------
sub tok_decrypt_rmc($) {
   my ($token) = @_;

   # pull header from token and parse out it's two values
   my ($hdr, $tok) = split(quotemeta($opts{keys}{aric_header_delimiter}), $token);
   my $map_version = hex(substr($hdr,0,2));  # first two bytes, in hex
   my $map_id      = substr($hdr,2); # map key

   if ( $map_version != $opts{keys}{aric_version} ) {
      die("$E: Unable to decrypt token: aric_version missmatch.\n"
         ."    key file aric_version = " . $opts{keys}{aric_version} 
         . ", token aric_version = $map_version\n");
   }

   # length of rmc map id is the length strings it maps to or from
   my $len = length($map_id);

   # chunk the string into equal parts of $len length
   my $plaintext;
   foreach my $chunk ( unpack("(a$len)*", $tok) ) {
      $plaintext .= $rmc_rmap{$map_id}{"$chunk"}; 
   }

   return $plaintext;

}



# ---------------------------------------------------------------------------
# create XO (eXecution Owner) token 
# ---------------------------------------------------------------------------
sub tok_encrypt_xo($) {
   my ($plaintext) = @_;

   my $cipher = Crypt::CBC->new(
         -key           => $opts{keys}{xo_cipher_key},
         -literal_key   => 0,  # treat -key as a passphrase, not the literal encryption key
         -cipher        => $opts{keys}{xo_cipher_algo},
         #-salt          => $cipher_salt,
         #-iv            => $opts{keys}{cipher_salt},
         -iv            => $opts{keys}{iv},
         -header        => 'none',
   );

   return $cipher->encrypt_hex($plaintext);
}


# ---------------------------------------------------------------------------
# decrypt XO (eXecution Owner) token 
# ---------------------------------------------------------------------------
sub tok_decrypt_xo($) {
   my ($ciphertext) = @_;

   my $cipher = Crypt::CBC->new(
         -key           => $opts{keys}{xo_cipher_key},
         -literal_key   => 0,  # treat -key as a passphrase, not the literal encryption key
         -cipher        => $opts{keys}{xo_cipher_algo},
         #-salt          => $cipher_salt,
         -iv            => $opts{keys}{iv},
         -header        => 'none',
   );

   return $cipher->decrypt_hex($ciphertext);
}

# ---------------------------------------------------------------------------
# create DO (Data Owner) token 
# ---------------------------------------------------------------------------
sub tok_encrypt_do($) {
   my ($plaintext) = @_;

   my $cipher = Crypt::CBC->new(
         -key           => $opts{keys}{do_cipher_key},
         -literal_key   => 0,  # treat -key as a passphrase, not the literal encryption key
         -cipher        => $opts{keys}{do_cipher_algo},
         #-salt          => $cipher_salt,
         #-iv            => $opts{keys}{cipher_salt},
         #-iv            => $opts{keys}{iv},
         #-header        => 'none',
   );

   return $cipher->encrypt_hex($plaintext);
}


# ---------------------------------------------------------------------------
# decrypt DO (Data Owner) token 
# ---------------------------------------------------------------------------
sub tok_decrypt_do($) {
   my ($ciphertext) = @_;

   my $cipher = Crypt::CBC->new(
         -key           => $opts{keys}{do_cipher_key},
         -literal_key   => 0,  # treat -key as a passphrase, not the literal encryption key
         -cipher        => $opts{keys}{do_cipher_algo},
         #-salt          => $cipher_salt,
         #-iv            => $opts{keys}{iv},
         #-header        => 'none',
   );

   return $cipher->decrypt_hex($ciphertext);
}


# ---------------------------------------------------------------------------
# Add more bytes to the noise map
# ---------------------------------------------------------------------------
sub add_noise($) {
   dbg(4, "adding noise\n", 2);
   return Digest::SHA::sha512_hex($_[0]);
}

# ---------------------------------------------------------------------------
# Build the in-memory random map dictionary
#
# Currently we generate one map for each $len. We could however, generate
# multiple maps for each $len, which would give us much greater "randomness".
# ---------------------------------------------------------------------------
sub build_rmc_map() {
   dbg(2, "Generating rmc maps\n");

   ## default char_map max length
   #my $max_strlen = 4;
   #if ( defined($opts{keys}{rmc_max_char_map_length}) ) {
   #   $max_strlen = int($opts{keys}{rmc_max_char_map_length});
   #}
   my $max_strlen = int($opts{keys}{rmc_max_char_map_length});

   # default to all 7-bit ASCII printable characters 
   # see http://perldoc.perl.org/perlrecharclass.html#POSIX-Character-Classes
   my @input_domain = ();
   foreach my $chr ( map {chr} (0..127) ) {
      #next if ( $chr =~ /[|\\]/ );  # exclude a few problematic characters
      #push(@input_domain, $chr) if $chr =~ m/\p{XPosixPrint}/; # full range unicode (will work for > 127)
      push(@input_domain, $chr) if $chr =~ m/[[:print:]]/;    # ascii range
   }
   if ( defined($opts{keys}{rmc_input_domain}) ) {
      @input_domain = split('', $opts{keys}{rmc_input_domain});
   }
   dbg(2, "number of character in the input domain: " . scalar @input_domain . "\n", 2);
   dbg(2, "input domain: " . join('',@input_domain) . "\n", 2);

   # Greg's input here! What is the minimum string length of output characters
   # we need to represent every character in the input domain.
   #my $min_strlen = POSIX::ceil(log(scalar(@input_domain))/log(scalar(@output_domain)));
   my $min_strlen = POSIX::ceil(log(scalar(@input_domain))/log(16));  # assume all 16 hex chars will be in map_noise
   if ( $max_strlen < $min_strlen ) {
      die("$E: unable to represent all intput domain characters with the\n"
        . "current output domain, using a max length of $max_strlen\n");
   }

   # generate the map and reverse map
   # the map is a HoH data structure where: 
   #  substr of the DO password hash (n bytes long) => {
   #     input_domain character => map string (n bytes long)   # for maps
   #     OR
   #     map string (n bytes long) => input domain character   # for reverse maps
   #  }
   $opts{keys}{do_pw_hash} = Digest::MD5::md5_hex($opts{keys}{do_cipher_key});
   my $i = 0;
   foreach my $len ($min_strlen .. $max_strlen) {
      dbg(3, "building rmc map for len $len\n");

      # generate bytes of predictable noise for this len
      my $pw_noise_key = substr($opts{keys}{do_pw_hash}, 0, $len);
      my $map_noise = add_noise($pw_noise_key . $opts{keys}{rmc_salt});
      dbg(4, "map_noise[$pw_noise_key] (" . length($map_noise) . " bytes): $map_noise\n", 2);

      foreach my $c ( @input_domain ) {
         $map_noise .= add_noise($map_noise) if ( $i + $len > length($map_noise) );
         my $str = substr($map_noise, $i++, $len);
         until ( ! exists($rmc_rmap{$pw_noise_key}{$str}) ) {
            $map_noise .= add_noise($map_noise) if ( $i + $len > length($map_noise) );
            $str = substr($map_noise, $i++, $len) 
         }
         $rmc_rmap{$pw_noise_key}{$str} = $c;
         $rmc_map{$pw_noise_key}{$c} = $str;
      }
      dbg(3, "  len $len: map_noise index = " . ($i + $len) . " out of " . length($map_noise) . "\n", 2);
      $i = 0;
   }
   #print "MAP: " . Dumper(\%rmc_map);
   #print "RMAP: " . Dumper(\%rmc_rmap);
   #$opts{rmc_map} = \%rmc_map;
   #$opts{rmc_rmap} = \%rmc_rmap;
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
