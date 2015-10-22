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
our @EXPORT_OK = qw(tok_encrypt_rmc tok_decrypt_rmc tok_encrypt_xo tok_decrypt_xo);

use strict;
use warnings;
use Crypt::CBC;
#use Digest;
#use Digest::MD5 qw(md5_hex);
#use Digest::SHA qw(sha512_hex);
use Data::Dumper;
use ARC::Common;
use ARC::Common qw($E);

# prototypes
sub add_noise($);
sub build_rmc_map();
sub set_rmc_options();
sub tok_encrypt_rmc($$);
sub tok_decrypt_rmc($);
sub tok_encrypt_xo($);
sub tok_decrypt_xo($);
# exportable
sub init_tokenizer(%);
sub tokenize_strings($);
sub detokenize_strings($);
# obsolete
sub random_str($@);
sub generate_map_table($$);

# globals
my %opts = ();




# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
sub init_tokenizer(%) {
   my ($href) = @_;
   %opts = %$href;
   #print "TOK INIT:\n" . Dumper(\%opts) . "\n";

   set_rmc_options();
   build_rmc_map();
}


# ---------------------------------------------------------------------------
# tokenzie every string in the array ref
# ---------------------------------------------------------------------------
sub tokenize_strings($) {
   my ($arrayref) = @_;

   # 1) create RMC tokens of each individual string

   # pick a random map table key to use for all strings in this batch
   # OJO: NOT very efficient to be called per row... need to optimize
   my @keys = keys $opts{rmc_map};
   my $map_id = $keys[int(rand(scalar @keys))];

   my @arr = map {
      my $f = tok_encrypt_rmc($_, $map_id); # generate RMC token
      #$f = tok_encrypt_xo($f);   # generate XO token
      $f; 
   } @$arrayref;
   if ( $opts{'output-rmc'} ) { return @arr; }

   # 2) concatenate all RMC tokens
   my $rmc = join($opts{keys}{rmc_token_delimiter}, @arr);

   # encrypt entire RMC token string to create XO token
   my @xo = map {
      tok_encrypt_xo($_); # generate XO token
#      my $f = tok_encrypt_xo($_); # generate XO token

      # concatenate map_id as an xo token header
      #$map_id . $opts{keys}{rmc_delimiter} . $f; 
#      $f;
   } ($rmc);

   return @xo;
}

# ---------------------------------------------------------------------------
# detokenzie every string in the array ref
# ---------------------------------------------------------------------------
sub detokenize_strings($) {
   my ($arrayref) = @_;

   # decrypt entire XO token
   my @arr = map {
      my $f = tok_decrypt_xo($_); # level 2
      #$f = tok_decrypt_rmc($f);   # level 1
      $f; 
   } @$arrayref;

   # 2) parse out RMC tokens
   my @rmc = split(quotemeta($opts{keys}{rmc_token_delimiter}), $arr[0]);

   # decrypt RMC tokens
   my @plaintext = map { tok_decrypt_rmc($_); } @rmc;

   return @plaintext;
}


# ---------------------------------------------------------------------------
# create RMC token (Random Map Cipher)
#
# For each token
# ---------------------------------------------------------------------------
sub tok_encrypt_rmc($$) {
   my ($plaintext, $map_id) = @_;

   # token header format = VVS*:
   # where:
   #   VV   = map table version number in hex
   #   S*   = variable length string, map table key (substr of DO password hash)
   my $token = sprintf("%02X", $opts{keys}{rmc_version}) . $map_id . $opts{keys}{rmc_delimiter};

   # character by character, replace original with mapped value from map_id row
   foreach my $c ( split('', uc($plaintext)) ) {
      # TODO: Need to print the record this is from to log file and warn that character $c was dropped
      $token .= $opts{rmc_map}{$map_id}{$c} || '';  # drop character if not found in map
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
   my ($hdr, $tok) = split(quotemeta($opts{keys}{rmc_delimiter}), $token);
   my $map_version = hex(substr($hdr,0,2));  # first two bytes, in hex
   my $map_id = substr($hdr,2); # map key

   if ( $map_version != $opts{keys}{rmc_version} ) {
      die("$E: Unable to decrypt token: rmc_version missmatch.\n"
         ."    key file rmc_version = " . $opts{keys}{rmc_version} 
         . ", token rmc_version = $map_version\n");
   }

   # length of rmc map id is the length strings it maps to or from
   my $len = length($map_id);

   # chunk the string into equal parts of $len length
   my $plaintext;
   foreach my $chunk ( unpack("(a$len)*", $tok) ) {
      $plaintext .= $opts{rmc_rmap}{$map_id}{"$chunk"}; 
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
# each version of rmc has different options. Set those here
# 
# MUST run AFTER parse_key_file().
# ---------------------------------------------------------------------------
sub set_rmc_options() {
   # we MUST run AFTER parse_key_file().
   die("$E: rmc_version is not defined in the key file!\n")
      unless( exists($opts{keys}{rmc_version}) );

   if ( $opts{keys}{rmc_version} == 3 ) {
      $opts{keys}{rmc_delimiter} = ':';
      $opts{keys}{rmc_token_delimiter} = '|';
   }
   else {
      die("$E: unknown rmc_version\n");
   }
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
# ---------------------------------------------------------------------------
sub build_rmc_map() {
   dbg(2, "Generating rmc maps\n");

   # default char_map max length
   my $max_strlen = 4;
   if ( defined($opts{keys}{rmc_max_char_map_length}) ) {
      $max_strlen = int($opts{keys}{rmc_max_char_map_length});
   }

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
   my %rmc_map = ();
   my %rmc_rmap = ();
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
   $opts{rmc_map} = \%rmc_map;
   $opts{rmc_rmap} = \%rmc_rmap;
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
