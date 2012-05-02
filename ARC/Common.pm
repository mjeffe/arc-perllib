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
our @EXPORT = qw(say dbg zpad get_datetime_str rr lotto open_ro_file close_file system_call get_record list_minus list_union list_uniq list_intersect);
#our @EXPORT_OK = qw();

use strict;
use warnings;
use POSIX qw(SIGINT);


# prototypes
sub dbg($$;$);
sub say($$;$);
sub zpad($$;$);
sub rr($$);
sub get_datetim_str();
sub lotto();
sub open_ro_file($);
sub close_file($);
sub system_call($$);
sub get_record($);
sub list_minus($$);
sub list_union($$);
sub list_uniq($);
sub list_intersect($$);


# can (and should) be set by any 'use'er of this module
our $verbose = 0;     # See note in say() about this!
our $E = 'ERROR';


# ---------------------------------------------------------------------------
# grabs one line from the open file handle
# expects an open filehandle parameter
# not recommended for reading an entire file, but useful for grabbing the header row
# ---------------------------------------------------------------------------
sub get_record($) {
   my ($fh) = @_;
   die("$E: get_record() called with an invalid file handle\n") if ( ! fileno($fh) );
   chomp(my $record = <$fh>);
   return $record;
}


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
sub system_call($$) {
   my ($cmd, $app) = @_;

   # simplistic approach
   #print "CMD: $cmd\n" if ( $opts{verbose} > 0 );
   #my $rc = system($cmd);
   #if ( ($rc >>= 8) != 0 ) {
   #   die("$E: $app failed with return code $?: $!\n");
   #}


   # more robust approach
   my $rc = system("$cmd");

   # did system call fail because Ctrl-C killed it?
   if ( ($rc & 127) == SIGINT ) {
      print STDERR "\nCtrl-C trapped!\n";
      die("\n");
      #SIGINT_handler();
   }
   # could not execute?
   elsif ( $rc == -1 ) {
      print STDERR scalar localtime, ": ERROR - failed to execute '$app': $!\n";
      die("\n");
      #bailout();
   }
   # step itself failed?
   elsif ($rc) {
      my $ret = $rc >> 8;
      print STDERR scalar localtime, ": ERROR - '$app' failed with return code $ret\n";
      die("\n");
      #bailout();
   }
}



# ---------------------------------------------------------------------------
# open file and return reference to file handle.
# can handle compressed files.
# ---------------------------------------------------------------------------
sub open_ro_file($) {
   my ($file) = @_;

   # Newer versions of Perl already do this, but just to be safe...
   if ( $file eq '-' ) {
      return \*STDIN;
   }

   if ( $file =~ m/.gz$/ ) {
      open(INPUT, "gzip -dcf $file |") or die("$E: Cannot open file $file: $!\n");
   } else {
      open(INPUT, "<", $file) or die("$E: cannot open file $file: $!\n");
   }

   return \*INPUT;
}

# ---------------------------------------------------------------------------
# close an open file handle
# ---------------------------------------------------------------------------
sub close_file($) {
   my ($fh) = @_;

   if ( $fh == \*STDIN || $fh == \*STDOUT ) {
      return;
   }
   close($fh) or die("$E: cannot close input file: $!\n");
}



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
#
# NOTE: You should set ARC::Common::verbose from the calling application before
# calling this (or the dbg) function!
# ---------------------------------------------------------------------------
sub say($$;$) {
   my $lvl = shift;
   my $msg = shift;
   my $indent = shift || 0;

   if ( $lvl <= $verbose ) {
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
      die("$E: problem in ARC::Common::get_datetime_str()\n");
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

# -----------------------------------------------------------------------------
# Returns array composed of all elements in A that are not in B
# Note: elements are normalized to lower case for comparrison!
# -----------------------------------------------------------------------------
sub list_minus($$) {
  my ($listref_a, $listref_b) = @_;
  my @list;
  my %hash;

  map { $hash{lc($_)} = ''; } @$listref_b;
  return grep { ! exists $hash{lc($_)} } @$listref_a;
}

# -----------------------------------------------------------------------------
# Returns an array composed of all unique elements in A and B
# Note: elements are normalized to lower case for comparrison!
# -----------------------------------------------------------------------------
sub list_union($$) {
  my ($listref_a, $listref_b) = @_;
  my @full_list = (@$listref_a, @$listref_b);
  my %uniq_hash;

  foreach my $f (@full_list) {
    if ( ! exists $uniq_hash{lc($f)} ) {
      $uniq_hash{lc($f)} = '';
    } 
  }
  
  return (keys %uniq_hash);
}


# -----------------------------------------------------------------------------
# Returns an array composed of all unique elements in A
# Note: elements are normalized to lower case for comparrison!
# -----------------------------------------------------------------------------
sub list_uniq($) {
  my ($listref_a) = @_;
  my @dummy = ();
  
  return list_union($listref_a, \@dummy);
}


# -----------------------------------------------------------------------------
# Returns list composed of all elements in both A and B
# Note: elements are normalized to lower case for comparrison!
# -----------------------------------------------------------------------------
sub list_intersect($$) {
  my ($listref_a, $listref_b) = @_;
  my @list;
  my %hash;

  map { $hash{lc($_)} = ''; } @$listref_b;
  return grep { exists $hash{lc($_)} } @$listref_a;
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
