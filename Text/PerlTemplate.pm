# ------------------------------------------------------------------------
# $Id$
#
# Replacement for Text::ScriptTemplate in Text code.
# 
# TODO:
#  - fill in this header
#  - Add perldoc
#  - Possibly set OUTPUT_EVAL_BUFF to a file name rather than boolean.  But
#    then we would have to come up with a scheme to avoid clobbering files.
# ------------------------------------------------------------------------

=head1 NAME

Text::PerlTemplate - A simple template parser in the style of jsp or php

=head1 SYNOPSIS

 use Text::PerlTemplate;

 print Text::PerlTemplate::parseFromFile($filename); # send output to stdout
 
 use Text::PerlTemplate "parse";             # import the parse() function

 # define a set of variables you want to use in the template
 our $table_name = "customer_tb";
 our %parms = (foo => "a", bar => "b");
 
 my $output = parse($filename);             # capture output
 print parse($fh);                          # use file handle rather than filename
 print parse(\*STDIN);                      # acts like a file handle
 
 # define your own delimiters.
 $Text::PerlTemplate::OPENING_DELIMITER = '[[';
 $Text::PerlTemplate::CLOSING_DELIMITER = ']]';
 
 # Dump the eval buffer to a file named PerlTemplate_debug.pl
 $Text::PerlTemplate::OUTPUT_EVAL_BUFF = 1;  # may be useful for debugging

=head1 DESCRIPTION

This module is useful for dynamically building output based on a template file.
It allows you to embed Perl between special delimiters, within a text file in
the style of jsp, asp or php.  This module will then parse, interpret and
replace those sections of the template to produce the output.

By default, the "<%" and "%>" tags delimit any Perl code, although these can be
redefined by the user.  If the opening delimiter includes an equal sign, as in
"<%= %>", any code or variables found between these delimiters is interpreted
and the result placed back into the output.  Without the equal sign, the Perl
code will still be executed, but any result string will be discarded.  These
blocks are generally used for control structures or for defining functions and
variables.  Any actions taken or variables set in a block, persist through to
subsequent blocks.

I<Text::PerlTemplate> works by creating a Perl script in an internal buffer.
This buffer is filled with the different elements of what it finds in the
template.  Any non-Perl code is simply quoted, and added to the buffer.  Any
Perl code in a "<%= %>" block is put in a Perl do() function and added to the
buffer.  All other Perl code is simply added to the buffer as is.  Finally, the
buffer is eval'ed and the output returned.

Note that since the code buffer is eval'ed within the I<main> package, any
variables that you define in your script and wish to use in the template, need
to be declared in the I<main> namespace or as globals with I<our> (assuming you
are not running within a different package).

=head1 USAGE AND EXAMPLES

Here are several examples of syntax and useful features provided by the module.

=over 4

=item *

Perl variables or normal environment variables can be substituted into your
template.  For example, in the following SQL template, you can substitute in
the environment variable TABLE_NAME.

  select * from <%= $ENV{TABLE_NAME} %>;

Which, given the environment variable TABLE_NAME=customer_tb would produce:

   select * from customer_tb;

=item *

Perl flow control structures can be used within your template, including if
statements and loops.  The syntax may look a little odd, as the opening brace
for the control statement will be between one set of delimiters and the closing
brace between another set, as in this SQL template.

  select *
  <% if ($var == 1) { %>
    from table_a
  <% } else { %>
    from table_b
  <% } %>
  ;

=item *

Perl functions can be used to gain additional functionality.  These may be
pulled in via Perl modules, defined in the calling script or defined in the
template itself.  For example, using the script:

  use Text::PerlTemplate;

  our $file_list_owner = "matt jeffery";
  our %dog_breeds = (
     dalmation => "/tmp/dogs/dalmation.txt",
     dachshund => "/tmp/dogs/dachshund.txt",
     mutt      => "/home/mjeffe/mydog.txt",
  );
  
  print Text::PerlTemplate::parseFromFile(shift);  

on the following snippet of an HTML template:

   <%
      use File::Basename;
 
      sub titlecase {
         return join(" ", map { ucfirst(lc($_)) } split(/\s/,shift));
      }
   %>
 
   <h1>Files owned by <%= titlecase($file_list_owner); %></h1>
   <hr>
   <table>
      <tr><td>Breed</td><td>File Name</td></tr>
   <% foreach my $dog (sort keys %dog_breeds) { %>
      <tr><td><%= $dog %></td><td><%= basename($dog_breeds{$dog}) %></td></tr>
   <% } %>
   </table>

would produce:

   <h1>Files owned by Matt Jeffery</h1>
   <hr>
   <table>
      <tr><td>Breed</td><td>File Name</td></tr>
      <tr><td>dachshund</td><td>dachshund.txt</td></tr>
      <tr><td>dalmation</td><td>dalmation.txt</td></tr>
      <tr><td>mutt</td><td>mydog.txt</td></tr>
   </table>

=item *

Space in the template occupied by "<% %>" blocks is removed from the output
rather than leaving blank space in it's place.  Space in the template occupied
by a "<%= %>" block will be replace with whatever that block evaluates to, so
it may increase or decrease the amount of space occupied by the block.  So that
the template:

   <%
      # my $name = "Matt";
      my $today = qx/date/;
      chomp $today;
      $today = "\n-----------------------------\n$today\n-----------------------------";
   %>

   Hello:
   <% 
      if (!defined($name)) {
   %>
      Mr. No Name.
   <% } else { %>
      Mr. <%= $name %>.
   <% } %>
   The date is: <%= $today %>
   Goodbye

Would generate the following output:

   Hello:
      Mr. No Name.
   The date is: 
   -----------------------------
   Thu Oct  9 10:47:46 CDT 2008
   -----------------------------
   Goodbye


=back

=head1 VARIABLES

The following variables are available.

=over 4

=cut

package Text::PerlTemplate;
require Exporter;

our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parseFromFile parseFromBuffer OUTPUT_EVAL_BUFF OPENING_DELIMITER CLOSING_DELIMITER);

use strict;
use warnings;
use Carp;
use FileHandle;

=item I<$OUTPUT_EVAL_BUFF>

If set, write eval buffer (described above) to a file named
PerlTemplate_debug.pl.  This is the Perl script that will be eval'ed to produce
the output.  There are a few lines that will be added to the buffer (marked
with comments) if this option is turned on, so that the script could actually
execute independently.  This is included as it may be helpful for debugging or
understanding how this module works.

=cut
our $OUTPUT_EVAL_BUFF = 0;

=item I<$OPENING_DELIMITER> and I<$CLOSING_DELIMITER>

These default to "<%" for the opening delimiter and "%>" for the closing delimiter, but
you can set them to whatever you like.  Be sure to escape characters that may confuse Perl.
For example, if you set them to php style "<?" and "?>", you will have to escape the "?" like this:

   $Text::PerlTemplate::OPENING_DELIMITER = '<\?';
   $Text::PerlTemplate::CLOSING_DELIMITER = '\?>';

=cut
our $OPENING_DELIMITER = '<%';
our $CLOSING_DELIMITER = '%>';

# result of eval'ing the eval buffer
my $eval_output = '';

# prototypes
sub load($);
sub add_to_buffer($);
sub print_eval_buffer();
sub parseFromFile($);
sub parseFromBuffer($$);
sub parse($$);



=head1 FUNCTIONS

=cut

# ------------------------------------------------------------------------
# loads the template and slurps in entire contents.  Takes either a file name
# or file handle.
sub load($) {
    my $file = shift;
    my $filename;
    
    if ( ref($file) ) {
        my $fd = fileno $file;
        # this will only work on GNU/Linux, but if it fails will display the file descriptor
        $filename = readlink("/proc/$$/fd/$fd");
        if (!defined $filename or $filename =~ m/^pipe:/) {
            $filename = '(' . (('STDIN', 'STDOUT', 'STDERR')[$fd] || "File descriptor $fd") . ')';
        } 
    } else {
        $filename = $file;
        $file = new FileHandle($file) || croak("$!");
    }
    
   # slurp in the entire input file.  I know, I know... not very efficient,
   # but it makes parsing a lot easier than doing it line by line...
   my $fbuff = '';
   while (my $line = <$file> ) {
      $fbuff .= $line;
   }
   return ($filename, $fbuff);
}


# ------------------------------------------------------------------------
# Adds text to a temporary buffer, which will eventually be eval'ed. Warns if
# nothing is passed, and reports the file name and line number from which null
# data was passed.
sub add_to_buffer($) {
   my ($str) = @_;
   if ( !defined($str) ) {
      my ($package, $filename, $line) = caller;
      warn "Use of uninitialized value in $filename at line $line\n";
   } else {
      $eval_output .= $str;
   }
}


# ------------------------------------------------------------------------
# for use with debugging - is used with OUTPUT_EVAL_BUFF
sub print_eval_buffer() {
   print $eval_output;
}

sub parseFromFile($) {
    my $file = shift;
    my ($filename, $buff) = load($file);
    return parse($filename, $buff);
}

sub parseFromBuffer($$) {
    my ($filename, $buff) = @_;
    return parse($filename, $buff);
}

# ------------------------------------------------------------------------
# Primary functionality of this package.

=item I<parse()>

This takes a file name or file handle as an argument and returns the parsed and
filled in template.  It parses the template file, searching for code
delimiters.  It builds a buffer of Perl code that is then eval'ed at the end to
produce final output.

=cut
sub parse($$) {
   my ($filename, $buff)  = @_;

   my $doblock = 0;  # flags a '<%=' block
   my $lineno = 1;   # line numbers in template file

   # don't want to die when undefined variables are used in the template code
   no strict;

   # start of code buffer to be eval'ed
   my $code = qq{package main;\n#line 1 $filename};

   my $D = $OPENING_DELIMITER;
   while ( $buff =~ s/^(.*?)$D//ms ) {
      my $hold = $1;

      # keep track of line numbers in template file
      $lineno++ while $hold =~ /\n/g;

      # is this a <%= block?
      if ( $D eq $OPENING_DELIMITER && $buff =~ s/^=//ms ) {
         $doblock = 1;
      }

      # found opening delimiter, save gobbled text from template file and start
      # a code block
      if ( $D eq $OPENING_DELIMITER ) {
         # need to escape any { or } in the gobbled text since we are using them
         # for delimiters in the q{ } construct
         $hold =~ s/'/\\'/g;

         $code .= "\nText::PerlTemplate::add_to_buffer('$hold');";
         $code .= qq{\n#line $lineno "$filename"\n};

         if ( $doblock ) {
            $code .= "Text::PerlTemplate::add_to_buffer(do { ";
         }
      }
      # found closing delimiter, save gobbled Perl code and close the code block
      else {
         $code .= "$hold";
         if ( $doblock ) {
            $code .= " }); ";
         }

         # Strip out "code only" lines from the template file, unless this was
         # a <%= block.  For example, we want to strip the newline from the end
         # of this:
         #   <% use Text::PerlTemplate %>
         # so that we do not leave a blank line in the output.  But do not srip
         # the newline from this:
         #   <%= $foo %>
         # since a value will be inserted, and we don't want it to be
         # concatenated with the next line.
         if ( ! $doblock ) {
            $lineno++ if ( $buff =~ s/(^\s*?\n)// );
         }

         $doblock = 0;
      }

      # toggle delimiter we are looking for
      $D = ($D eq $CLOSING_DELIMITER) ? $OPENING_DELIMITER : $CLOSING_DELIMITER;

   }

   # add remaining text (from last %> to EOF)
   $buff =~ s/'/\\'/g;
   $code .= "\nText::PerlTemplate::add_to_buffer('$buff');";

   if ( $OUTPUT_EVAL_BUFF ) {
      open(FH, ">", "PerlTemplate_debug.pl") or die "can't open debug file...\n";
      print FH "# Run `perl PerlTemplate_debug.pl' to execute. # Added to debug output\n";
      print FH "use Text::PerlTemplate;                         # Added to debug output\n";
      print FH "use Env;                                       # Added to debug output\n";
      print FH $code, "\n";
      print FH "Text::PerlTemplate::print_eval_buffer();        # Added to debug output\n";
      close(FH);
   }
   eval $code;
   croak $@ if ($@);

   return $eval_output;
}

=head1 INSTALLATION / REQUIREMENTS

Like any Perl module, make sure your PERL5LIB environment variable is set to
wherever this is installed, which if you got to this message using perldoc it
probably is set already.

=head1 NOTES / BUGS

Delimited Perl code blocks cannot be nested.

=head1 AUTHORS

Matt Jeffery (mjeffe@acxiom.com) and Russell Reed (rreed@acxiom.com)

Please send us any bug reports or enhancement requests.

=cut

1
