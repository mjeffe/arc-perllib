# ---------------------------------------------------------------------------
# $Id$
# 
# load and save Perl module style config files in the style of the CPAN
# module's ~/.cpan/CPAN/MyConfig.pm config file.
#
# load() and save() are not exported since the names are too generic.
# You can use them with a fully qualified name: 
#
#   ARC::Config::load($file)
#
# or, you can choose to import them using:
#
#   use ARC::Config qw(load save);
#
# ---------------------------------------------------------------------------

package ARC::Config;
require Exporter;

# export functions and variables
our @ISA = qw(Exporter);
#our @EXPORT = qw(load save);
our @EXPORT_OK = qw(load save);

use strict;
use warnings;
use Data::Dumper;

# prototypes
sub load($);
sub save($$;$$);


# ---------------------------------------------------------------------------
# load a config file which is a perl module, in the style of CPAN's MyConfig.pm
#
# Some implementation references
#    http://docstore.mik.ua/orelly/perl/cookbook/ch08_17.htm
#    http://www.perlmonks.org/?node_id=464358
#
# Anything loaded from the config file that does not have a namespace defined,
# will end up in the ARC::Config namespace and can be referenced from the
# calling program like this:
#
#   $ARC::Config::somevar.
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
#   $ARC::Output::CONFIG = {
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
# Now, once ARC::Config::load($file) has been called, the calling program can
# reference it's config like this:
#
#   %scores = %ARC::Config::SCORES;
#   print $scores{name} . "'s scores: " . join(",", $scores{scores}) . "\n";
#
#   if ( $ARC::Output::CONFIG->{save_state} =~ m/TRUE/i ) {
#      %conf = %{ $ARC::Output::CONFIG };  # dereference the hash ref
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
