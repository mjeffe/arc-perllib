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
our @EXPORT = qw(standardize_pii);
our @EXPORT_OK = qw(init standardize_name standardize_ssn standardize_dobymd);

use strict;
use warnings;
#use Time::Piece;     # core module, but will not parse dates outside epoch range (1902 - 2038 ish)
use POSIX::strptime; # non-core module. bummer...
use Data::Dumper;
use ARC::Common qw(dbg esay);

# prototypes
# exportable
sub init(%);
sub standardize_pii($);
sub standardize_name($);
sub standardize_ssn($);
sub standardize_dobymd($);

# globals
my %opts = ();
my @invalid_ssn_patterns = ();
my $E = "Standardizer ERROR";
my $W = "Standardizer WARNING";

our $VERSION = 0.1;



# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
sub init(%) {
   my ($href) = @_;
   %opts = %$href;
   dbg(2, "Standardizer init...\n");

   # ??? define the order of fields we expect to see in standardize_pii?

   # define invalid ssn patterns
   @invalid_ssn_patterns = (
      qr/^[8-9]/,
      qr/^000/,
      qr/^[0-7][0-9][0-9]00/,
      qr/^[0-7][0-9][0-9][0-9][0-9]0000/,
      qr/0000000/,
      qr/1111111/,
      qr/2222222/,
      qr/3333333/,
      qr/4444444/,
      qr/5555555/,
      qr/6666666/,
      qr/7777777/,
      qr/8888888/,
      qr/9999999/,
      qr/1234567/,
      qr/9876543/
   );
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
#
# Essentially, drop everything non-alpha with a few exceptions
# The special list of chars are preserved as spaces since they are important
# word separators.
# ---------------------------------------------------------------------------
sub standardize_name($) {
   my ($s) = @_;

   # Note:
   #  tr// is more efficient than s// so use when possible
   #  tr// does not interpolate regexes (except the - range operator)
   my $str = uc($s);                # to upper case
   $str =~ tr/A-Z ()\/,-//cd;       # drop everything not in list (alphas and a few special chars)
   $str =~ tr/()\/,/ /;             # convert special chars to space
   $str =~ s/\s*-\s+|\s+-\s*/ /g;   # convert - to space, unless it is in a word
   $str =~ tr/ / /s;                # collapse any white space into a single space
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

   $s =~ tr/- //d;             # strip any space or - characters

   # look for invalid patterns
   my $valid = 1;             # assume valid

#   if ( length($s) != 9 ) { $valid = 0; }
#   if ( $s ~~ @invalid_ssn_patterns ) { $valid = 0 };   # smart match (perlfaq6: How do I efficiently match...)
#                                                        # OR
#   foreach my $pattern ( @invalid_ssn_patterns ) {      # match patterns in loop
#      if ( $s =~ m/$pattern/ ) {
#         $valid = 0;
#         last;
#      }
#   }

   # remarkably, this is about 2-4 times faster than using the precomplied
   # @invalid_ssn_patterns techniques
   if    ( length($s) != 9 ) { $valid = 0; }
   elsif ( $s =~ m/0000000/) { $valid = 0; }
   elsif ( $s =~ m/^[8-9]/ ) { $valid = 0; }
   elsif ( $s =~ m/^000/   ) { $valid = 0; }
   elsif ( $s =~ m/^[0-7][0-9][0-9]00/) { $valid = 0; }
   elsif ( $s =~ m/^[0-7][0-9][0-9][0-9][0-9]0000/) { $valid = 0; }
   elsif ( $s =~ m/1111111/) { $valid = 0; }
   elsif ( $s =~ m/2222222/) { $valid = 0; }
   elsif ( $s =~ m/3333333/) { $valid = 0; }
   elsif ( $s =~ m/4444444/) { $valid = 0; }
   elsif ( $s =~ m/5555555/) { $valid = 0; }
   elsif ( $s =~ m/6666666/) { $valid = 0; }
   elsif ( $s =~ m/7777777/) { $valid = 0; }
   elsif ( $s =~ m/8888888/) { $valid = 0; }
   elsif ( $s =~ m/9999999/) { $valid = 0; }
   elsif ( $s =~ m/1234567/) { $valid = 0; }
   elsif ( $s =~ m/9876543/) { $valid = 0; }

   #return ($valid, $s);
   esay(1, "$W: invalid ssn($s) on record $main::recid\n") unless($valid);
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

   # can handle dates from the year 0000 - 9999
   my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday) = POSIX::strptime($s, $opts{'dob-format'});
   if ( defined($year) && defined($mon) && defined($mday) ) {
      return sprintf("%d%02d%02d", $year+1900, $mon+1, $mday);
   }
   
   esay(1, "$W: error parsing date ($s) on record $main::recid\n");
   return '';
}


1;
