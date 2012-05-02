# ---------------------------------------------------------------------------
# $Id$
# 
# Common functions used by ARC utilities
#
#   use ARC::Common;
#
# ---------------------------------------------------------------------------

package ARC::IDCrypt;
require Exporter;

# export functions and variables
our $VERSION = '0.01';
our @ISA = qw(Exporter);
our @EXPORT = qw(encrypt decrypt);
our @EXPORT_OK = qw(OTP encrypt32 encrypt32 dec2bin32 bin2dec32);

use strict;
use warnings;
use bignum;
#use Math::BigInt;
use Math::BigInt lib => 'GMP';

# prototypes
sub encrypt32($$);
sub decrypt32($$);
sub encrypt($$);
sub decrypt($$);
sub OTP($$);

# can (and should) be set by any 'use'er of this module
our $debug = 0;     # See note in say() about this!
our $E = 'ERROR';

# TIM GLOBALS
#use constant OFFSET     => 1410000000;
use constant OFFSET     => 1000000000;
use constant MAXINT     => 8589934591 + OFFSET;
my $bits = 33;


# ---------------------------------------------------------------------------
# Normal encrypt method.  This can handle an id of any size, but expects
# ---------------------------------------------------------------------------
sub encrypt($$) {
   my ($ID, $PW) = @_;

   if ( $ID > MAXINT || $ID < OFFSET ) {
      die("$E: id ($ID) is outside of allowable range " . OFFSET . " - " . MAXINT . "\n");
   }

   # convert to bit strings
   # trim off the leading 0b added by as_bin()
   # pre-pend leading zeros to make a fixed length string, $bits long
   #print "bits:" . 1x$bits . "\n";   # reference line
   #my $id = sprintf("%0${bits}s", substr(Math::BigInt->new($ID - OFFSET)->as_bin(), 2));
   my $id = Math::BigInt->new($ID) - OFFSET;
   $id = sprintf("%0${bits}s", substr($id->as_bin(), 2));
   my $pw = sprintf("%0${bits}s", substr(Math::BigInt->new($PW)->as_bin(), 2));
   print "id   : $id\n" if ($debug);;
   print "pw   : $pw\n" if ($debug);;

   # reverse the id bit string
   $id = scalar reverse $id;
   print "id  r: $id\n" if ($debug);;

   # bitwise xor with the pw bitstring
   my $xor = unpack("B$bits", (pack("B$bits", $id) ^ pack("B$bits", $pw)));
   print "xor  : $xor\n" if ($debug);;

   # convert bitstring back to a number
   return Math::BigInt->new("0b$xor") + OFFSET;
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
sub decrypt($$) {
   my ($ID, $PW) = @_;

   if ( $ID > MAXINT || $ID < OFFSET ) {
      die("$E: id ($ID) is outside of allowable range OFFSET - MAXINT\n");
   }

   #my $id = sprintf("%0${bits}s", substr(Math::BigInt->new($ID)->as_bin(), 2));
   my $id = Math::BigInt->new($ID) - OFFSET;
   $id = sprintf("%0${bits}s", substr($id->as_bin(), 2));
   my $pw = sprintf("%0${bits}s", substr(Math::BigInt->new($PW)->as_bin(), 2));
   print "id   : $id\n" if ($debug);;
   print "pw   : $pw\n" if ($debug);;

   # bitwise xor with the pw bitstring
   my $xor = unpack('B33', (pack('B33', $id) ^ pack('B33', $pw)));
   print "xor  : $xor\n" if ($debug);;

   # reverse the id bit string
   $xor = scalar reverse $xor;
   print "xor r: $xor\n" if ($debug);;

   # convert bitstring back to a number
   return Math::BigInt->new("0b$xor") + OFFSET;
}



# ---------------------------------------------------------------------------
# slick and fast, but can only handle up to 32 bit integers
# ---------------------------------------------------------------------------
sub encrypt32($$) {
   my ($id, $pw) = @_;

   if ( $id > MAXINT || $id < OFFSET ) {
      die("$E: id ($id) is outside of allowable range OFFSET - MAXINT\n");
   }

   $id = scalar reverse sprintf("%032b", $id);
   $pw = sprintf("%032b", $pw);
   print "id  r: $id\n" if ($debug);;
   print "pw   : $pw\n" if ($debug);;

   my $xor = unpack('B32', (pack('B32', $id) ^ pack('B32', $pw)));
   print "xor  : $xor\n" if ($debug);;

   return oct("0b$xor") + OFFSET;
}

# ---------------------------------------------------------------------------
# slick and fast, but can only handle up to 32 bit integers
# ---------------------------------------------------------------------------
sub decrypt32($$) {
   my ($id, $pw) = @_;

   if ( $id > MAXINT || $id < OFFSET ) {
      die("$E: id ($id) is outside of allowable range OFFSET - MAXINT\n");
   }

   $id = sprintf("%032b", $id);
   $pw = sprintf("%032b", $pw);
   print "id   : $id\n" if ($debug);;
   print "pw   : $pw\n" if ($debug);;

   my $xor = unpack('B32', (pack('B32', $id) ^ pack('B32', $pw)));
   print "xor  : $xor\n" if ($debug);;

   $xor = scalar reverse $xor;
   print "xor r: $xor\n" if ($debug);;

   return oct("0b$xor") + OFFSET;
}


# lifted from Crypt::OTP
sub OTP($$) {
   my ($pad_text, $message) = @_;

   while ( length( $pad_text ) < length( $message ) ) {
      $pad_text .= $pad_text;
   }
   my @message = split ( //, $message );
   my @pad     = split ( //, $pad_text );
   my $cipher;

   for ( my $i = 0 ; $i <= $#message ; $i++ ) {
      #$cipher .= pack( 'C', unpack( 'C', $message[ $i ] ) ^ unpack( 'C', $pad[ $i ] ) );
      $cipher .= ( unpack('C', $message[$i]) ^ unpack('C', $pad[$i]) );
   }
   return $cipher;
}

# can only handle 32 bits
sub dec2bin32($) {
    my $str = unpack("B32", pack("N", shift));
    return $str;
}
sub bin2dec32($) {
   return unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
}


## inspired by: http://www.perlmonks.org/?node_id=163123
## returns 64-bit wide bitstrings
#use Bit::Vector;
#sub dec2bin($) {
#   my $vec = Bit::Vector->new_Dec(64, shift);
#   my $str = unpack("B64", pack 'NN', $vec->Chunk_Read(32, 32), $vec->Chunk_Read(32, 0));
#   return substr($str, -33);
#}
#
#sub bin2dec($) {
#   my $vec = Bit::Vector->new_Dec(64, shift);
#   my $str = unpack("B64", pack 'NN', $vec->Chunk_Read(32, 32), $vec->Chunk_Read(32, 0));
#   return substr($str, -33);
#}



1;
