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
our @EXPORT = qw(parse_key_file encrypt_key_file);
#our @EXPORT_OK = qw(init);

use strict;
use warnings;
use Crypt::OpenPGP;
use Data::Dumper;
use ARC::Common qw(dbg prompt);

# prototypes
sub parse_key_file($;$);
sub decrypt_key_file($;$);
sub encrypt_key_file($);

# globals
#my %opts = ();
my $E = "Keyfile ERROR";
my $W = "Keyfile WARNING";

our $VERSION = 0.1;



## ---------------------------------------------------------------------------
## ---------------------------------------------------------------------------
#sub init(%) {
#   my ($href) = @_;
#   %opts = %$href;
#   #print "TOK INIT:\n" . Dumper(\%opts) . "\n";
#}


# ---------------------------------------------------------------------------
# Get config information from the provided key file
#
# The key file contains configuration options that are security sensitive, such
# as encryption keys, salt, etc. This file is itself encrypted and the
# user running this program will be prompted for the password to decrypt it
#
# The key file structure a plain old key=value config file.  Each line in the
# file can be one of:
#  1) blank line - nothing but whitespace
#  2) a comment line - any line where the first not whitespace character is #
#  3) a line with key = value, where:
#        - a key is a contiguous string of non-whitespace characters
#        - all white space before the key, and surrounding the = is ignored.
#        - all white space following the first non-whitespace character after the = is preserved. 
#
#        For example:
#
#           # this comment line is valid
#           my_key         =  some string of characters
#      
#           my_key2   = someother string   # this comment is not valid
#           my_key3=foo
#      
#           # the following line will be silently ignored (white space in the key)
#           bad key = something
#
#     Would parse as: 
#     
#     $VAR1 = {
#               'my_key' => 'some string of characters',
#               'my_key2' => 'someother string   # this comment is not valid',
#               'my_key3' => 'foo',
#             };
#
#
# ---------------------------------------------------------------------------
sub parse_key_file($;$) {
   my ($keyfile, $passphrase) = @_;

   # set up parameters I will need when parsing key file
   my %keys = ();
   my $kf = decrypt_key_file($keyfile, $passphrase);
   dbg(2, "parsing key file $keyfile...\n");
   my @kf = split("\n", $kf);
   foreach my $line (@kf) {
      next if $line =~ m/^\s*#/;   # ignore any comment lines
      next if $line =~ m/^\s*$/;  # ignore any blank lines

      # parse "key = value" lines
      if ( $line =~ m/^\s*(\w+)\s*=\s*(.+)/ ) {
         $keys{$1} = $2;
      }
   }

   # Do not check for required keys here, rather let each module that uses the
   # keyfile check for their own required parameters

   dbg(4, "Keyfile keys:\n" . Dumper(\%keys));
   return \%keys;
}



# ---------------------------------------------------------------------------
# Decrypt the key file
# NOTE:
# key file should be encrypted with GPG or PGP using symetric-key CAST5 cipher
# ---------------------------------------------------------------------------
sub decrypt_key_file($;$) {
   my ($keyfile, $passphrase) = @_;
   dbg(2, "decrypting key file $keyfile...\n");

   my %args = (
      #Data        => $ciphertext,
      Filename    => $keyfile,
   );
   if ( $passphrase ) {
      $args{Passphrase} = $passphrase;
   } else {
      $args{PassphraseCallback}  = sub { prompt("PEARL key file password:", 1); };
   }

   my $pgp = Crypt::OpenPGP->new;
   my $text = $pgp->decrypt(%args);
   unless ( $text ) {
      if ( $pgp->errstr =~ /Bad checksum/ ) {
         die "Decryption failed: Bad passphrase\n";
      } else {
         die "Decryption failed: ", $pgp->errstr unless $text;
      }
   }
   dbg(4, "contents of decoded key file:\n<<<BEGIN DECODED KEY FILE>>>\n$text\n<<<END DECODED KEY FILE>>>\n");
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
   # TODO: should check if we can use zenity, else
   #    die("$E: unable to run graphical password prompt, run 'gpg -c key_file.txt > key_file.txt.gpg' instead");
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


1;
