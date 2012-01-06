# ---------------------------------------------------------------------------
# $Id$
# 
# load and save of config files for KIM
# may need to expand this into some generic perl file loader and unloader,
# but for now, it just does CONFIG.
# ---------------------------------------------------------------------------

package KIM::Config;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
our @EXPORT = qw(load_config save_config);

use strict;
use warnings;
use Data::Dumper;

# prototypes
sub load_config($);
sub save_config($$);


# ---------------------------------------------------------------------------
# load our config file.  
# The config file is a perl module, in the style of CPAN's MyConfig.pm
#
# Some implementation references
#    http://docstore.mik.ua/orelly/perl/cookbook/ch08_17.htm
#    http://www.perlmonks.org/?node_id=464358
#
# Anything loaded from the config file will end up in the KIM::Config namespace
# (unless of course the config file defines objects in some other namespace),
# and can be reference from the calling program like 
#
#   $KIM::Config::somevar.
#
# For convenience, load_config() looks for the $CONFIG hash ref and passes that
# back.  That means the config file needs to contain at least: 
#
#   $CONFIG = {};
#
# We may want to change this behavior to not return anything...
#
# Call us like this:
#
#   $conf = load_config($file);
#   print "Something:  $conf->{somevar}{someother} \n";
# 
# Or, dereference the return:
# 
#   %conf = %{ load_config($file) };
#   print "Something:  $conf{somevar}{someother} \n";
#
# ---------------------------------------------------------------------------
sub load_config($) {
   my $fname = shift;

   # load and eval
   my $rc = do($fname);

   # Check for errors
   if ($@) {
      die("ERROR: Failure compiling config '$fname' - $@");
   } elsif (! defined($rc)) {
      die("ERROR: Failure reading config '$fname' - $!");
   } elsif (! $rc) {
      die("ERROR: Failure processing config '$fname'");
   }

   return($KIM::Config::CONFIG);
}


# ---------------------------------------------------------------------------
# may want to return something if error
# NOTE: This line can be used inside of a here doc, but I don't fully
# understand it, so I'm not going to use it.
#
#   @{[Data::Dumper->Dump([$config], ['CONFIG'])]}
#
# Implement a third optional parameter to take a name, rather than the default
# CONFIG string.  Or it may be better to implement similar options
# as Data::Dumper::Dump() - that is anonymous array refs:
#
#  [array of configs], [array of files], [array of strings]
#
# need some way to put them all in one file though.
#
# ---------------------------------------------------------------------------
sub save_config($$) {
   my ($config, $fname) = @_;


   # load and eval
   open(OUT, '>', $fname) || die("ERROR: Unable to open '$fname' - $!");

   my $now = `date`; chomp($now);
   print OUT <<EOF;
# ###########################################################################
# KIM config file
# Contains options from $config->{KIM_BASEDIR}/conf/kim.conf
# as well as dynamically generated parameters
# saved at: $now
# ###########################################################################

EOF

   print OUT Data::Dumper->Dump([$config], ['CONFIG']);
   print OUT "\n1;\n__END__\n";

   close(OUT) || die("ERROR: Unable to close '$fname' - $!");
   return(undef);

}

1;
