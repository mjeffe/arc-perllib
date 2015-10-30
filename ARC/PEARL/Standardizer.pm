# ---------------------------------------------------------------------------
# $Id$
# 
# This module encapsulates functionality for standardizing data to be used in
# PEARL, before encryping as tokens.
#
# ---------------------------------------------------------------------------

package ARC::PEARL::Standardizer;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
# export functions
our @EXPORT = qw(init_standardizer standardize_pii standardize_name standardize_ssn standardize_dobymd);
#our @EXPORT_OK = qw();

use strict;
use warnings;
#use Time::Piece;     # core module, but will not parse dates outside epoch range (1902 - 2038 ish)
use POSIX::strptime; # non-core module. bummer...
use Data::Dumper;
use ARC::Common;
use ARC::Common qw($E $W);

# prototypes
# exportable
sub init_standardizer(%);
sub standardize_pii($);
sub standardize_name($);
sub standardize_ssn($);
sub standardize_dobymd($);

# globals
my %opts = ();




# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
sub init_standardizer(%) {
   my ($href) = @_;
   %opts = %$href;
   #print "TOK INIT:\n" . Dumper(\%opts) . "\n";
   
   # define the order of fields we expect to see in standardize_pii?
   #
}


# ---------------------------------------------------------------------------
# standardize every string in the array ref
#
# Expects strings in the order: fname, lname, ssn, dobymd
# ---------------------------------------------------------------------------
sub standardize_pii($) {
   my ($arrayref) = @_;
   my @pii = ();

   push(@pii, standardize_name($arrayref->[0]));
   push(@pii, standardize_name($arrayref->[1]));
   push(@pii, standardize_ssn($arrayref->[2]));
   push(@pii, standardize_dobymd($arrayref->[3]));
   return @pii;
}

# ---------------------------------------------------------------------------
# standardize name (first or last) fields
# ---------------------------------------------------------------------------
sub standardize_name($) {
   my ($s) = @_;

   my $str = uc($s);
   $str =~ tr/()\/,/ /;             # convert specific chars to space
   $str =~ s/\s*-\s+|\s+-\s*/ /g;   # convert - to space, unless it is in a word
   $str =~ s/\s+/ /g;               # collapse any white space into a single space
   $str =~ s/^\s+|\s+$//;           # trim leading and trailing space

   return $str;
}


# ---------------------------------------------------------------------------
# standardize SSN
#
# returns 2 element array: (is_valid_flag, standardized_ssn)
# ---------------------------------------------------------------------------
sub standardize_ssn($) {
   my ($s) = @_;

   #$s =~ tr/[^0-9]//;        # strip any non numeric characters
   #my $valid = ( length($s) == 9 ) ? 1 : 0;

   $s =~ tr/ -//;             # strip any space or - characters
   my $valid = 0;             # assume invalid

   if (  length($s) == 9
      && substr($s,0,1) != '8' 
      && substr($s,0,1) != '9'
      && substr($s,0,3) != '000'
      && substr($s,3,2) != '00'
      && substr($s,5,4) != '0000'
   ) {
      $valid = 1;
   }

   # these are all 7 digis... is KIM's is_valid_ssn() function wrong?
#   if    ( $s eq "0000000") { $valid = 0; }
#   elsif ( $s eq "1111111") { $valid = 0; }
#   elsif ( $s eq "2222222") { $valid = 0; }
#   elsif ( $s eq "3333333") { $valid = 0; }
#   elsif ( $s eq "4444444") { $valid = 0; }
#   elsif ( $s eq "5555555") { $valid = 0; }
#   elsif ( $s eq "6666666") { $valid = 0; }
#   elsif ( $s eq "7777777") { $valid = 0; }
#   elsif ( $s eq "8888888") { $valid = 0; }
#   elsif ( $s eq "9999999") { $valid = 0; }
#   elsif ( $s eq "1234567") { $valid = 0; }
#   elsif ( $s eq "9876543") { $valid = 0; }

   #return ($valid, $s);
   return $s;
}

# ---------------------------------------------------------------------------
# standardize date into YYYYMMDD
#
# parse date bassed on format, then return string reformated to our standard
# ---------------------------------------------------------------------------
sub standardize_dobymd($) {
   my ($s) = @_;

   return $s if ( $s eq '' );
   return $s if ( $opts{'dob-format'} eq "%Y%m%d" );

   # can only handle dates within the valid epoch range (1902 - 2038 ish)
   #my $dt = eval { return Time::Piece->strptime($s, $opts{'dob-format'}); };
   #if ( $@ ) {
   #   print "$E: standardize_dobymd($s): $@";
   #   return '';
   #}
   #return $dt->ymd('');

   #my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday) = POSIX::strptime("string", "Format");
   my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday) = POSIX::strptime($s, $opts{'dob-format'});
   if ( defined($year) && defined($mon) && defined($mday) ) {
      return sprintf("%d%02d%02d", $year+1900, $mon+1, $mday);
      #my $d = sprintf("%d%02d%02d", $year+1900, $mon+1, $mday);
      #print "PARSING: $s, GOT: $d\n";
      #return $d;
   }
   
   print "$W: error parsing date ($s) on record $main::recid\n";
   return '';
}


1;
