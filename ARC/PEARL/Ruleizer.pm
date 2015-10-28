# ---------------------------------------------------------------------------
# $Id$
# 
# This module is as yet, undefined. The idea is to add additional fields to the
# pii before tokenizing. These fields would facilitate matching once we no
# longer have access to the pii. For example, valid_ssn flag, last 4 of ssn,
# etc. These would also be tokenized, so we would not actually have the last 4
# of ssn, but we would be able to do token matching to determin whether or not
# the last 4 are the same.
#
# ---------------------------------------------------------------------------

package ARC::PEARL::Ruleizer;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
# export functions
our @EXPORT = qw(init_ruleizer add_rules);
#our @EXPORT_OK = qw();

use strict;
use warnings;
use Data::Dumper;
use ARC::Common;
use ARC::Common qw($E);

# prototypes
# exportable
sub init_ruleizer(%);
sub add_rules($);

# globals
my %opts = ();




# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
sub init_ruleizer(%) {
   my ($href) = @_;
   %opts = %$href;
   #print "TOK INIT:\n" . Dumper(\%opts) . "\n";
}


# ---------------------------------------------------------------------------
# standardize every string in the array ref
#
# Expects strings in the order: fname, lname, ssn, dobymd
# ---------------------------------------------------------------------------
sub add_rules($) {
   my ($arrayref) = @_;

   # currently, uniplemented
   return @$arrayref;
}



1;
