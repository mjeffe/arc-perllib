# ---------------------------------------------------------------------------
# $Id$
# 
# Common functions used by ARC utilities
#
#   use ARC::Common;
#
# ---------------------------------------------------------------------------

package ARC::Common;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
#our @EXPORT = qw(load save);
our @EXPORT_OK = qw(say dbg zpad get_datetime_str rr lotto);

use strict;
use warnings;

# prototypes
sub dbg($$;$);
sub say($$;$);
sub zpad($$;$);
sub rr($$);
sub get_datetim_str();
sub lotto();


# ---------------------------------------------------------------------------
# standardize debug messages.
# see say()
# ---------------------------------------------------------------------------
sub dbg($$;$) {
   my $lvl = shift;
   my $msg = shift;
   my $indent = shift || 0;

   say($lvl, (scalar localtime) . ": " . " " x $indent . "$msg", 0);
}

# ---------------------------------------------------------------------------
# standardize our output messages.
# parm1: verbose level at which this message is printed
# Parm2: string to print
# parm3: number of spaces to indent
# ---------------------------------------------------------------------------
sub say($$;$) {
   my $lvl = shift;
   my $msg = shift;
   my $indent = shift || 0;

   if ( $lvl <= $opts{verbose} ) {
      print STDOUT " " x $indent . "$msg";
   }
}

# ---------------------------------------------------------------------------
# returns fixed length, zero prefixed number.  
# does not truncate, so if the number is longer than $len, just returns $num.
# examples: 
#   zpad(12,4) returns 0012
#   zpad(12345,4) returns 12345
# it also works for arbitrary strings, so:
#   zpad('abc',5) returns  00abc
# and you can provide the pad character, so:
#   zpad('abc',5,'_') returns  __abc
# ---------------------------------------------------------------------------
sub zpad($$;$) {
   my ($num, $len, $pad) = @_;
   $pad = $pad || '0';

   return $pad x ($len - length($num)) . $num;
}


# ---------------------------------------------------------------------------
# Once again, trying to avoid external dependencies such as Date::Calc,
# although, we could use POSIX::strftime I suppose.
# Returns string of the current datetime in the format: YYYYMMDD_HHMMSS
# ---------------------------------------------------------------------------
sub get_datetime_str() {

   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
   $year += 1900;
   $mon  = zpad($mon + 1, 2);
   $mday = zpad($mday + 1, 2);
   $hour = zpad($hour, 2);
   $min  = zpad($min, 2);
   $sec  = zpad($sec, 2);

   #return "${year}${mon}${mday}_${hour}${min}${sec}"; 

   # since I roll-my-own, I had better validate
   my $str = "${year}${mon}${mday}_${hour}${min}${sec}";
   if ( length($str) != 15 ) {
      die("$E: problem in get_datetime_str()\n");
   }

   return $str;
}


# ------------------------------------------------------------------------
# random range
# ------------------------------------------------------------------------
sub rr($$) {
   my ($min, $max) = @_;
   return int(rand($max)) + $min;
}

# ------------------------------------------------------------------------
# predict lottery winner
# ------------------------------------------------------------------------
sub lotto() {
   print "Your Arkansas Lottery Mega Millions winning numbers are:\n";
   print "Connecting."; sleep 1; print "."; sleep 1; print "."; sleep 1; print "."; sleep 1; print ".\n";
   print rr(1,55) . " "; sleep 1;
   print rr(1,55) . " "; sleep 1;
   print rr(1,55) . " "; sleep 1;
   print rr(1,55) . " "; sleep 1;
   print rr(1,55) . " "; sleep 1;
   print "and the Mega Ball is ";
   print rr(1,55) . "\n";
   exit 0;
}


1;
