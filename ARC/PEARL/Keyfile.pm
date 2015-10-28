# ---------------------------------------------------------------------------
# $Id$
# 
# This module encapsulates the code necessary to encrypt, decrypt and parse
# the pearl runtime key file. This key file is used by pearl as well as
# several of pearl's supporting modules, such as the tokenizer, etc.
#
# ---------------------------------------------------------------------------

package ARC::PEARL::Keyfile;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
# export functions
our @EXPORT = qw(parse_key_file);
#our @EXPORT_OK = qw();

use strict;
use warnings;
use Crypt::OpenPGP;
use Term::ReadKey;   # for messing with ReadMode in password prompting
use Data::Dumper;
use ARC::Common;
use ARC::Common qw($E);

# prototypes
sub parse_key_file($);
sub encrypt_key_file($);
sub decrypt_key_file($);
sub pgp_passphrase_cb();

# globals
my %opts = ();




## ---------------------------------------------------------------------------
## ---------------------------------------------------------------------------
#sub init_keyfile(%) {
#   my ($href) = @_;
#   %opts = %$href;
#   #print "TOK INIT:\n" . Dumper(\%opts) . "\n";
#}


# ---------------------------------------------------------------------------
# Get config information from the provided key file
#
# The key file contains configuration options that are security sensitive, such
# as encryption keys, rmc map table, etc. This file is itself encrypted and the
# user running this program will be prompted for the password to decrypt it
#
# The key file structure consists of key = value pairs as well as sections of
# data delimited by special [] tags. Blank lines and comment lines begging with
# a '#' character are allowed. For example:
#
#    # eXecution Owner encryption algorithm and password
#    xo_cipher_algo = Rijndael
#    xo_cipher_key  = My secret password
#    #xo_cipher_salt = Use this to keep encrypted values consistent, however reduces security of tokens
#
#    # Data Owner encryption algorithm and password (password is likely blank as we don't know it)
#    do_cipher_algo = Rijndael
#    do_cipher_key  = 
#
#    # character used to delimit the RMC header from the RMC value.
#    # MUST NOT be one of the characters in the rmc map id 0 row
#    rmc_delimiter = :
#    rmc_version = 1
#    [rmc_map_begin]
#    0|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9
#    1|PN|T1|CV|7C|DG|MT|U4|BI|6Y|SE|BQ|8Q|G6|BW|OO|7D|YG|AG|Y2|0W|MF|UU|OU|1U|Q3|MX|8I|EO|T4|20|DY|LW|G2|XZ|P4|2I
#    2|5|J|F|A|C|4|L|B|R|S|0|9|3|2|Z|O|I|V|8|Y|Q|7|U|N|M|W|6|H|T|D|P|K|1|X|G|E
#    ...
#    [rmc_map_end]
#
# RMC Map Table structure:
#    An RMC map table defines a series of mappings between ASCII characters in
#    the first (reference) row and a series of random strings of varying
#    lengths in the subsequent rows. It should have the following structure:
#
#     * All rows are a series of pipe (|) delimited strings of lenght >= 1
#     * The first column of every table should have the map type ID. This is a
#       sequence number starting with 0.  
#     * The first row of every table should be the reference row, consisting of
#       the map type ID = 0, followed by all ASCII characters you want mapped
#       by the RMC cipher. Any character not listed in this reference row will
#       not be mapped, but left as-is.
#     * Each subsequent row in the table should have a column to match one in
#       the reference row, which contains a string. Each string in the row
#       should have the same length, and be unique within that row. Each row
#       can have a different string length.
#     * NOTE it is possible to only have row 0 in the table. This is
#       essentially a NO-MAP table. That is A = A, B = B, etc. Useful for
#       debugging and testing.
# ---------------------------------------------------------------------------
sub parse_key_file($) {
   my ($keyfile) = @_;

   # set up parameters I will need when parsing key file
   my %keys = ();
   my $rmc_section = 0;
   my @rmc_map_ref_row = ();
   my %rmc_map = ();
   my $kf = decrypt_key_file($keyfile);
   my @kf = split("\n", $kf);
   foreach my $line (@kf) {
      next if $line =~ m/^\s*#/;   # ignore any comment lines
      next if $line =~ m/^\s*$/;  # ignore any blank lines

      # parse "key = value" lines
      if ( $line =~ m/^\s*(\w+)\s*=\s*(.+)/ ) {
         $keys{$1} = $2;
      }
   }

   # check for required keys
   my @required_keys = qw(
         aric_version rmc_salt
         xo_cipher_algo xo_cipher_key xo_cipher_salt
         do_cipher_algo
      );
   my @missing_keys = list_minus(\@required_keys, [keys %keys]);
   if ( (scalar @missing_keys) > 0 ) {
      die("$E: key file is missing required keys: " . join(', ', @missing_keys) . "\n");
   }
   # generate a 16 byte Initialization Vector from "salt"
   $keys{'iv'} = substr(Digest::MD5::md5_hex($keys{xo_cipher_salt}), 0, 16);
   #print "IV: " . $keys{iv} . "\n";

   dbg(3, "KEYS:\n" . Dumper(\%keys));
   dbg(3, "\n\n");
   dbg(3, "RMC MAP:\n" . Dumper(\%rmc_map));

   #$opts{'keys'} = \%keys;
   return \%keys;
}



# ---------------------------------------------------------------------------
# Decrypt the key file
# NOTE:
# key file should be encrypted with GPG or PGP using symetric-key CAST5 cipher
# ---------------------------------------------------------------------------
sub decrypt_key_file($) {
   my ($filename) = @_;

   my $pgp = Crypt::OpenPGP->new;
   my $text = $pgp->decrypt(
      #Data        => $ciphertext,
      Filename    => $filename,
      PassphraseCallback  => \&pgp_passphrase_cb,
   );
   unless ( $text ) {
      if ( $pgp->errstr =~ /Bad checksum/ ) {
         die "Decryption failed: Bad passphrase\n";
      } else {
         die "Decryption failed: ", $pgp->errstr unless $text;
      }
   }

   dbg(3, "DECODED KEY FILE:\n$text");
   return $text;
}


# ---------------------------------------------------------------------------
# Encrypt a plaintext key file
# NOTE:
#   This is a convenience function. It's just a substitute for:
#
#      gpg -c key_file.txt > key_file.txt.gpg
#
#   key file is encrypted using symetric-key CAST5 cipher
# ---------------------------------------------------------------------------
sub encrypt_key_file($) {
   my ($filename) = @_;

   # since we are probably called with output redirection: 
   #     piist --encrypt-key-file --key-file my.keys > my.keys.pgp
   # we can't prompt for password on stdout. Use zenity instead
   #my $pw = passphrase_cb();
   #my $pw = passphrase_cb();
   my $pw = `zenity --entry --hide-text --text="Passphrase for key file"`;
   my $pw2 = `zenity --entry --hide-text --text="Passphrase for key file"`;
   die "Passphrases do not match\n" if ( $pw ne $pw2 );
   chomp($pw);

   my $pgp = Crypt::OpenPGP->new;
   my $ciphertext = $pgp->encrypt(
      Cipher      => 'CAST5',
      Filename    => $filename,
      Passphrase  => $pw,
   );
   die "Encryption failed: ", $pgp->errstr unless $ciphertext;
   return $ciphertext;
}

# ---------------------------------------------------------------------------
# Callback function for Crypt::OpenPGP::decrypt which prompts user for password
# ---------------------------------------------------------------------------
sub pgp_passphrase_cb() {
   if ( exists($ENV{PIIST_KEYFILE_PASSWORD}) ) {
      return $ENV{PIIST_KEYFILE_PASSWORD};
   }
   print "Execution Owner Key File Passphrase: ";
   ReadMode('noecho');  # turn off echo to terminal
   my $pw = (<>);
   chomp($pw);
   ReadMode(0);         # back to normal
   print "\n";;
   return $pw;
}




1;
