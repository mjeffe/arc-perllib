# ---------------------------------------------------------------------------
# $Id$
# 
# load and save of config files for KIM
#
# load() and save() are generic - they load and save perl objects and are
# not exported.  load_config() and save_config() are specific to kim's
# main configuration. -- NOTE: they have moved back into kim's main executable
# ---------------------------------------------------------------------------

package KIM::Config;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
#our @EXPORT = qw(load_config save_config);
our @EXPORT = qw(load save);

use strict;
use warnings;
use Data::Dumper;

# prototypes
sub load_config($);
sub save_config($$);
sub load($);
sub save($$;$$);

# ---------------------------------------------------------------------------
# this has stuff specific to kim's main configuration file kim.conf
# ---------------------------------------------------------------------------
sub load_config($) {
   load(shift);
   #unless ( %{ $KIM::Config::CONFIG } ) {    # if CONFIG is hash ref
   unless ( %KIM::Config::CONFIG ) {         # if CONFIG is hash
      die("ERROR: Unknown problem loading config file\n");
   }
   #my $ref = $KIM::Config::CONFIG;      # if CONFIG is hash ref
   my $ref = \%KIM::Config::CONFIG;     # if CONFIG is hash

   # check for KIM_BASEDIR. Add it from the environment if it doesn't exist
   if ( ! exists($ref->{conf}{KIM_BASEDIR}) ) {
      $ref->{conf}{KIM_BASEDIR} = $ENV{KIM_BASEDIR};
   }
   
   #return(%KIM::Config::CONFIG);    # if CONFIG is hash ref
   return(%KIM::Config::CONFIG);    # if CONFIG is hash
}


# ---------------------------------------------------------------------------
# has kim specific stuff
sub save_config($$) {
   my ($file, $config) = @_;

   my $now = `date`; chomp($now);
   my $header = <<EOF;
# ###########################################################################
# KIM config file for jobid: $config->{KIM_JOBID}
# Contains options from $config->{KIM_BASEDIR}/conf/kim.conf
# as well as dynamically generated parameters
# saved at: $now
# ###########################################################################

EOF

   #save(@_, $header);
   save($file, [$config], ['CONFIG'], $header);
}

# ---------------------------------------------------------------------------
# load a config file which is a perl module, in the style of CPAN's MyConfig.pm
#
# Some implementation references
#    http://docstore.mik.ua/orelly/perl/cookbook/ch08_17.htm
#    http://www.perlmonks.org/?node_id=464358
#
# Anything loaded from the config file that does not have a namespace defined,
# will end up in the KIM::Config namespace and can be referenced from the
# calling program like this:
#
#   $KIM::Config::somevar.
#
# For example, if the config file contains:
#
#   # define a hash
#   %SCORES = (
#     'name'   => 'Matt',
#     'scores' => [10, 15, 12]
#   );
#
#   # define a hash ref in seperate namespace
#   $KIM::Output::CONFIG = {
#     'output_dir'   => '/tmp',
#     'log_file'     => 'kim.log',
#     'log_level'    => {
#        'warn'   => 0,
#        'error'  => 1,
#        'crit'   => 2
#     },
#     'save_state'   => 'TRUE'
#   };
#   
# Now, once load_config($file) has been called, the calling program can
# reference it's config like this:
#
#   %scores = %KIM::Config::SCORES;
#   print $scores{name} . "'s scores: " . join(",", $scores{scores}) . "\n";
#
#   if ( $KIM::Output::CONFIG->{save_state} =~ m/TRUE/i ) {
#      %conf = %{ $KIM::Output::CONFIG };  # dereference the hash ref
#      print "Output dir: " . $conf{output_dir} . ", Log Level for 'warn': " . $conf{log_level}{warn} . "\n";
#   }
#
#
# ---------------------------------------------------------------------------
sub load($) {
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

}


# ---------------------------------------------------------------------------
# may want to return something if error
# NOTE: This line can be used inside of a here doc, but I don't fully
# understand it, so I'm not going to use it.
#
#   @{[Data::Dumper->Dump([$config], ['CONFIG'])]}
#
# config_ref is an anonymous array of config objects to save.  config_names_ref
# is an optional anonymous array of names to assign to the config objects.
# Without this optional parameter, Data::Dumper will just call them VAR1, VAR2,
# etc. See Data::Dumper::Dump() (or more specifically, Data::Dumper::new()) for
# documentation on those two parameters.
#
# ---------------------------------------------------------------------------
sub save($$;$$) {
   my ($fname, $config_ref, $config_names_ref, $header) = @_;
   #my $fname = $_[0]
   #my $config_ref = $_[1];
   #my $config_names_ref = $_[2];
   #my $header = $_[3];


   open(OUT, '>', $fname) || die("ERROR: Unable to open '$fname' - $!");

   if ( $header ) {
      print OUT $header;
   }

   #print OUT Data::Dumper->Dump([$config], ['CONFIG']);
   print OUT Data::Dumper->Dump($config_ref, $config_names_ref);
   print OUT "\n1;\n__END__\n";

   close(OUT) || die("ERROR: Unable to close '$fname' - $!");
   return(undef);

}

1;
