# ----------------------------------------------------------------------------------
# $Id: Generate.pm,v 1.28 2010/08/23 21:29:26 rreed Exp $
# ----------------------------------------------------------------------------------

package SQL::Generate;

=head1 NAME

 SQL::Generate - Contains functions to generate bits of SQL

=head1 SYNOPSIS

use SQL::Generate;

 get_table_field_names($Template::database_handle, $table_name);
 get_table_field_names($Template::database_handle, $table_name, $schema);
 get_table_comment($Template::database_handle, $table_name, $schema);
 list_table_fields(\@field_list,
    table_alias     => 'a',
    suffix          => '_1',
    indentation     => '   ',
    no_column_alias => 1,
    exclude_columns => \@exclude_col_names
 );
 table_is_empty($Template::database_handle, $table_name, $schema);
 ($name,$schema,$link) = resolve_name($Template::database_handle, $table_name);
 %index = find_index($database_handle,$table_name,@index_columns);
 print $index{name}, $index{type}, $index{uniqueness};
 get_table_field_defs($Template::database_handle, $table_name, $schema);
 get_field_def($Template::database_handle, $field_name, $table_name, $schema);
 get_table_indexes($Template::database_handle, $table_name, $schema);

=head1 DESCRIPTION

This is used to generate bits of sql, using the template_sql executable. 
template_sql uses the Perl module Text::ScriptTemplate to parse sql files 
before passing the sql to sqlplus.

=head1 INSTALLATION / REQUIREMENTS

Make sure your PERL5LIB environment variable is set to wherever this is 
installed, which if you got to this message using perldoc it probably is set 
already.

=head1 METHODS

Following methods are currently available.

=over 4

=cut

require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(list_table_fields get_table_field_names get_field_names_from_file get_table_field_defs get_field_def table_is_empty get_table_comment resolve_name find_index get_table_indexes);
@EXPORT_OK = qw(list_minus list_intersect list_union list_uniq);

use DBI;

use strict;
use warnings;

sub resolve_name($$;$$$);

# -----------------------------------------------------------------------------

=item I<get_table_field_names($database_handle,$table_name,$schema);>

Parameters are:

 database handle - Established database connection.
 table           - The name of the table to list fields from.  May
                   be a table, view, or synonym, and may optionally
                   be qualified with a schema name.  May not include
                   a database link at this time.
 schema          - The table owner, optional unless it differs 
                   from the user we're connected as.  The schema may
                   be included in the table argument instead of
                   passing it as a separate argument.

Returns an array of field names

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub get_table_field_names($$;$)
{
  my ($dbh, $table_name, $schema) = @_;
  my @field_names;
  my $field_name;

  my $sth;
# if (! $schema) {  $schema = $dbh->get_info(47); }  # SQL_USER_NAME
  if ($schema) {
    $table_name = $schema . "." . $table_name;
  }

  $sth = $dbh->prepare("select * from $table_name where rownum < 1");

  @field_names = @{$sth->{NAME}};
  $sth->finish;

  if ($#field_names < 0) { die "No fields found for table $table_name"; }

  return @field_names;
}

# -----------------------------------------------------------------------------

=item I<get_table_comment($database_handle,$table_name,$schema);>

Parameters are:

 database handle - Established database connection.
 table           - The name of the table to fetch the comment for.  May
                   be a table or view, and may NOT be qualified with
                   a schema name.  May include a database link.
 schema          - The table owner, optional unless it differs 
                   from the user we're connected as.

Returns the comments as a string.  There is currently no way to distinguish
between a table with no comments and a non-existent table (or table without
sufficient privilege)

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub get_table_comment($$;$)
{
  my ($dbh, $table_name, $schema) = @_;

  my $db_link;
  ($table_name, $db_link) = split(/@/, $table_name, 2);

  if ($db_link) {
    $db_link = '@' . $db_link;
  }

  my $sql;
  my $sth;
  if ($schema) {
    $sth = $dbh->prepare("select comments from all_tab_comments${db_link}
                          where owner = ? and table_name = ?");
    $sth->execute(uc($schema), uc($table_name));
  } else {
    $sth = $dbh->prepare("select comments from user_tab_comments${db_link}
                          where table_name = ?");
    $sth->execute(uc($table_name));
  }

  my ($comment) = $sth->fetchrow_array();
  # Don't worry about whether the query failed to return any rows
  $sth->finish;

  return $comment;
}

# -----------------------------------------------------------------------------

=item I<list_table_fields(\@field_list, %optional_args);>

This function takes an array of field names and some optional 
parameters to format the list of fields for use in n sql statement.

Parameters are an array of field names, followed by arguments 
interpreted as a hash.

Hash entries may include:

 table_alias      - Table alias for this instance of the table.
 prefix           - A string to prepend to column names.
 suffix           - A string to append to column names.
 indentation      - Whitespace to begin each line with.
 no_column_alias  - Append prefix/suffix to the original field,
                    rather than creating an alias for the column
                    with the prefix/suffix.
 exclude_columns  - An array reference, listing fields not to 
                    include.

For example:

   list_table_fields(\@field_list,
       table_alias     => 'a',
       suffix          => '_1',
       indentation     => '   ',
       no_column_alias => 1,
       exclude_columns => \@exclude_col_names
    );

=cut
sub list_table_fields($%)
{
  my $fields = shift;
  my @fields = @$fields;  # dereference array pointer (essentially gets array from array reference)
  my %parms = @_;

  #die "Table argument must be supplied" unless ($parms{table});

  my @bad_keys = list_minus([keys %parms],
                     [ 'table_alias', 'prefix', 'suffix', 'indentation', 'no_column_alias', 'exclude_columns' ]);
  if ($#bad_keys >= 0) {
    die ("Unrecognized parameter(s) " . join(', ', @bad_keys));
  }

  my @keep_fields = list_minus(\@fields, $parms{exclude_columns});

  # Store the rest of the parameters in local variables, since we'll
  # be accessing them multiple times in the foreach loop
  my $table_alias = $parms{table_alias} || '';
  if ($table_alias) { $table_alias .= '.' }

  my $prefix = $parms{prefix} || '';
  my $suffix = $parms{suffix} || '';
  my $indentation = $parms{indentation} || '';

  if ( length($suffix) <= 0 && length($prefix) <= 0) {
    $parms{no_column_alias} = 1;
  }

  my @output_fields = ();
  my $field;
  foreach $field (@keep_fields) {
    if (exists $parms{no_column_alias}) {
      push @output_fields, ($table_alias . $prefix . $field . $suffix);
    } else {
      push @output_fields, ($table_alias . $field . ' AS ' . $prefix . $field . $suffix);
    }
  }

  return $indentation . join(",\n" . $indentation, @output_fields);
}

# -----------------------------------------------------------------------------

=item I<get_table_field_defs($database_handle,$table_name,$schema);>

Parameters are:

 database handle - Established database connection.
 table           - The name of the table to list fields from.  May
                   be a table, view, or synonym, and may optionally
                   be qualified with a schema name.  May not include
                   a database link at this time.
 schema          - The table owner, optional unless it differs 
                   from the user we're connected as.  The schema may
                   be included in the table argument instead of
                   passing it as a separate argument.

Returns an array of datatype definition strings (for example "varchar2(10)" or "date")

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub get_table_field_defs($$;$)
{
  my ($dbh, $table_name, $schema) = @_;
  my @field_defs;
  my $field_def;
  my $tab_columns = "user_tab_columns";
  my $sql;
  my $sth;
  my $db_link = "";

  ($table_name, $schema, $db_link) = resolve_name($dbh, $table_name, $schema);

# if (! $schema) {  $schema = $dbh->get_info(47); }  # SQL_USER_NAME
  if ($schema) {
    $tab_columns = "all_tab_columns";
  }

  if ( $db_link ) {
    $tab_columns .= "\@$db_link";
  }

  $sql =  "select column_name, data_type, data_length, data_precision, data_scale "
        . "from " . $tab_columns . " where table_name = '" . uc($table_name) . "'";

  if ($schema) {
    $sql .= " and owner = '" . uc($schema) . "'";
  }
  $sql .= " order by column_id";

  #print "\n\nSQL: $sql \n";
  $sth = $dbh->prepare($sql);
  $sth->execute();

  #@field_defs = @{$sth->{NAME}};
  while ( my @row = $sth->fetchrow_array ) {

     # field name
     $field_def = $row[0] . " ";

     # field type - taking into account data length, precision and scale
     if ( uc($row[1]) eq "DATE" ) {
       $field_def .= $row[1];
     }
     elsif ( uc($row[1]) eq "NUMBER" ) {
       $field_def .= $row[1];
       if ( defined($row[3]) ) {
         $field_def .= "(" . $row[3];
         if ( defined($row[4]) && $row[4] != 0 ) {
           $field_def .= "," . $row[4];
         }
         $field_def .= ")";
       }
     }
     else {
       $field_def .= $row[1] . "(" . $row[2] . ")";
     }
     push(@field_defs, $field_def);
  }
  $sth->finish;

  if ($#field_defs < 0) { die "No fields found for table $table_name"; }

  return @field_defs;
}

# -----------------------------------------------------------------------------

=item I<get_field_def($database_handle,$field_name,$table_name,$schema);>

Parameters are:

 database handle - Established database connection.
 field_name      - Name of the column.
 table_name      - The name of the table to list fields from.  May
                   be a table, view, or synonym, and may optionally
                   be qualified with a schema name.  May not include
                   a database link at this time.
 schema          - The table owner, optional unless it differs 
                   from the user we're connected as.  The schema may
                   be included in the table argument instead of
                   passing it as a separate argument.

Returns the datatype definition string (for example "varchar2(10)" or "date")

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub get_field_def($$$;$)
{
  my ($dbh, $field_name, $table_name, $schema) = @_;
  my $field_def = undef;
  my $tab_columns = "user_tab_columns";
  my $sql;
  my $sth;
  my $db_link;

  
  ($table_name, $schema, $db_link) = resolve_name($dbh, $table_name, $schema);

# if ( ! $schema ) {  $schema = $dbh->get_info(47); }  # SQL_USER_NAME
  if ( $schema ) {
    $tab_columns = "all_tab_columns";
  }

  if ( $db_link ) {
    $tab_columns .= "\@$db_link";
  }

  #$sql =  "select data_type, data_length from " . $tab_columns 
  #      . " where column_name = '" . uc($field_name) . "' and table_name = '" . uc($table_name) . "'";
  $sql =  "select data_type, data_length, data_precision, data_scale " . "from " . $tab_columns
        . " where column_name = '" . uc($field_name) . "' and table_name = '" . uc($table_name) . "'";
  if ( $schema ) {
    $sql .= " and owner = '" . uc($schema) . "'";
  }

  #print "\n\nSQL: $sql \n";
  $sth = $dbh->prepare($sql);
  $sth->execute();

  my @row = $sth->fetchrow_array();
  if (@row) {
     if ( uc($row[0]) eq "DATE" ) {
       $field_def .= $row[0];
     }
     elsif ( uc($row[0]) eq "NUMBER" ) {
       $field_def .= $row[0];
       if ( defined($row[2]) ) {
         $field_def .= "(" . $row[2];
         if ( defined($row[3]) && $row[3] != 0 ) {
           $field_def .= "," . $row[3];
         }
         $field_def .= ")";
       }
     }
     else {
       $field_def .= $row[0] . "(" . $row[1] . ")";
     }
  }

  $sth->finish;

  if ( ! defined($field_def) ) { die "Field $field_name or table $table_name not found"; }

  return $field_def;
}

# -----------------------------------------------------------------------------

# =item I<get_field_names_from_file($file_name);>
#
#Parameters are:
#
# file_name     - Name of the file.
#
#Returns an array of field names
#
# =cut
sub get_field_names_from_file($)
{
  my $control_card = shift;
  my @field_names;
  my $field_name;

  open(CTRLCARD, "<$control_card") or die "Can't open control card file $control_card";

  while (my $line = <CTRLCARD>) {
    # ignore blank lines and Perl style comments on a line by themselves
    if ( $line =~ /^\s*#/ || $line =~ /^\s*$/ ) { next; }

    # Trim space
    $line =~ s/^\s*//;  # ltrim
    $line =~ s/\s*$//;  # rtrim
    push @field_names, $line;
  }

  if ($#field_names < 0) { die "No fields found in control card $control_card"; }

  close(CTRLCARD);

  return @field_names;
}

# -----------------------------------------------------------------------------

=item I<table_is_empty($database_handle,$table_name,$schema);>

Parameters are:

 database handle - Established database connection.
 table           - The name of the table to list fields from.  May
                   be a table, view, or synonym, and may optionally
                   be qualified with a schema name.  May not include
                   a database link at this time.
 schema          - The table owner, optional unless it differs 
                   from the user we're connected as.  The schema may
                   be included in the table argument instead of
                   passing it as a separate argument.

Returns true if table is empty, false if it contains rows

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub table_is_empty($$;$)
{
  my ($dbh, $table_name, $schema) = @_;
  my @field_names;
  my $field_name;

  my $sth;
# if (! $schema) {  $schema = $dbh->get_info(47); }  # SQL_USER_NAME
  if ($schema) {
    $table_name = $schema . "." . $table_name;
  }

  $sth = $dbh->prepare("select /*+ parallel(a 1)*/ count(*) from $table_name a where rownum <= 1");
  $sth->execute();

  my ($cnt) = $sth->fetchrow_array();
  $sth->finish();

  if ($cnt == 0) { return 1; }

  return 0;
}

# -----------------------------------------------------------------------------

=item I<resolve_name($dbh,$object_name,$schema,$db_link,$depth);>

Parameters are:

 dbh             - Database handle
 object_name     - Name of the database object to resolve
                   May include schema and database link.
 schema          - Schema object is in.  Defaults to current schema.
 db_link         - Database link to remote database object exists in.
                   Not really supported currently.  You will probably
                   not get correct results.
 depth           - Recursion depth.  Used to prevent infinite recursion.
 

Returns an array containing the resolved object name, schema, and db link.

 TODO: Support public synonyms
 BUG: Oracle's all_synonyms view will not show you recursive synonyms
      owned by another user in some cases

=cut


sub resolve_name($$;$$$)
{
  my ($dbh, $object_name, $schema, $db_link, $depth) = @_;

  if (! defined($depth)) {
    $depth = 10;
  }

  if ($depth < 0) {
    die "Too much recursion while trying to resolve $object_name";
  }

  if (! defined($db_link)) {
    ($object_name, $db_link) = split /@/, $object_name;
    $db_link ||= '';
  }

  if (! defined($schema)) {
    ($schema, $object_name) = split /\./, $object_name;
    if (!defined($object_name)) {
      $object_name = $schema;
      $schema = '';
    }
  }

  if ($db_link) {
    die "Cannot currently resolve remote objects";
  }

  my $sth;
  if ($schema) {
    $sth = $dbh->prepare("
       select table_owner, table_name, db_link, object_type
       from all_synonyms a, all_objects b
       where a.TABLE_OWNER = b.OWNER and a.TABLE_NAME = b.OBJECT_NAME
	 and a.OWNER = ? and a.SYNONYM_NAME = ?");
    $sth->execute(uc($schema), uc($object_name));
  } else {
    $sth = $dbh->prepare("
       select table_owner, table_name, db_link, object_type
       from user_synonyms a, user_objects b
       where a.TABLE_NAME = b.OBJECT_NAME
	 and a.SYNONYM_NAME = ?");
    $sth->execute(uc($object_name));
  }

  my @results = $sth->fetchrow_array();
  $sth->finish();

  if (@results) {
    my $type;
    ($schema, $object_name, $db_link, $type) = @results;
 
    if ($type eq 'SYNONYM') {
      ($object_name, $schema, $db_link) = resolve_name($dbh, $object_name, $schema, $db_link, $depth-1);
    }
  }

  if (! $schema) {
    $sth = $dbh->prepare("select user from dual");
    $sth->execute();

    ($schema) = $sth->fetchrow_array();
    $sth->finish();
  }

  return (uc($object_name), uc($schema), uc($db_link));
}

# -----------------------------------------------------------------------------

=item I<find_index($database_handle,$table_name,@index_columns);>

Parameters are:

 database handle - Established database connection.
 table           - The name of the table to locate an index for.
                   The table name may optionally
                   be qualified with a schema name.  May not include
                   a database link at this time.  Synonyms will
                   be automatically resolved.
 index columns   - The list of field names the index should include.
                   Only an exact match will be accepted, though the
                   order the columns are listed in does not matter.

Returns a hash representing the index.  Currently, the hash only contains
'owner', 'name', 'type', and 'uniqueness' entries.

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub find_index($$@)
{
  my ($dbh, $table_name, @columns) = @_;
  my ($schema, $db_link);

  ($table_name, $schema, $db_link) = resolve_name($dbh, $table_name);

  if ($#columns + 1 <= 0) {
    die "Must provide list of columns for index";
  }

  if ($db_link) {
    die "Cannot currently find indexes on a remote table";
  }

  my $column_list = join(', ', map { "'" . uc($_) . "'" } @columns);
  my $column_count = $#columns + 1;

  my $sql;
  my $sth;
  $sth = $dbh->prepare("
    select a.owner, a.index_name, a.index_type, a.uniqueness
    from all_indexes a,
    (
      -- Find indexes with exactly the right set of columns
      -- Compare number of columns in index against number of matching columns
      select
        index_owner,
	index_name
      from all_ind_columns
      where table_owner = ? and table_name = ?
      group by index_owner, index_name
      having count(column_name) =
	count(case when column_name in ($column_list) then 1 end)
	and count(column_name) = $column_count
    ) b
    where a.owner = b.index_owner and a.index_name = b.index_name
  ");
  $sth->execute($schema, $table_name);

  my @results = $sth->fetchrow_array();
  $sth->finish;

  if (@results) {
    my ($owner, $name, $type, $uniqueness) = @results;
    return ('owner' => $owner, 'name' => $name, 'type' => $type,
            'uniqueness' => $uniqueness);
  } else {
    return;
  }
}

# -----------------------------------------------------------------------------

=item I<get_table_indexes($database_handle,$table_name,$schema);>

Parameters are:

 database handle - Established database connection.
 table           - The name of the table to list indexes from.  May
                   be a table, view, or synonym, and may optionally
                   be qualified with a schema name.  May not include
                   a database link at this time.
 schema          - The table owner, optional unless it differs 
                   from the user we're connected as.  The schema may
                   be included in the table argument instead of
                   passing it as a separate argument.

Returns a list of hashes representing the indexes.  Currently, the hashes 
contain 'owner', 'name', 'type', 'uniqueness', and 'columns' entries.

The 'columns' entry is itself a list of hashes, representing the columns
that make up the index.  Each column hash contains 'position', 'name',
'length', and 'order' entries.

B<NOTE:> template_sql provides a database handle called $Template::database_handle

=cut
sub get_table_indexes($$;$)
{
  my ($dbh, $table_name, $schema) = @_;

  my $db_link;

  ($table_name, $schema, $db_link) = resolve_name($dbh, $table_name, $schema);

  if ($db_link) {
    die "Cannot currently find indexes on a remote table";
  }

  my $sth = $dbh->prepare("
    select a.owner, a.index_name, a.index_type, a.uniqueness
    from all_indexes a
    where a.table_owner = ? and a.table_name = ?
  ");
  $sth->execute($schema, $table_name);

  my @indexes;
  while (my ($owner, $name, $type, $uniqueness) = $sth->fetchrow_array()) {
    my $sth2 = $dbh->prepare("
      select a.column_position, a.column_name, a.column_length, a.descend
      from all_ind_columns a
      where a.index_owner = ? and a.index_name = ?
      order by a.column_position
    ");
    $sth2->execute($owner, $name);

    my @columns;
    while (my ($position, $name, $length, $order) = $sth2->fetchrow_array()) {
      push @columns, {'position' => $position, 'name' => $name,
              'length' => $length, 'order' => $order};
    }
    $sth2->finish;

    push @indexes, {'owner' => $owner, 'name' => $name, 'type' => $type,
            'uniqueness' => $uniqueness, 'columns' => \@columns};
  }
  $sth->finish;

  return @indexes;
}

# -----------------------------------------------------------------------------
#
# Arguments:
#   List A (reference)
#   List B (reference)
#
# Returns list composed of all elements in A, but not in B

sub list_minus ($$)
{
  my ($listref_a, $listref_b) = @_;
  my @list;
  my %hash;

  map { $hash{uc($_)} = ''; } @$listref_b;
  return grep { ! exists $hash{uc($_)} } @$listref_a;

#  map { $hash{uc($_)} = ''; } @$listref_b;
#  map { unless (exists $hash{uc($_)}) { push @list, $_ } } @$listref_a;

}

# -----------------------------------------------------------------------------
#
# Arguments:
#   List A (reference)
#   List B (reference)
#
# Returns list composed of all unique elements in A and B

sub list_union ($$)
{
  my ($listref_a, $listref_b) = @_;
  my @full_list = (@$listref_a, @$listref_b);  # combine the lists
  my %uniq_hash;

  foreach my $f (@full_list) {
    if ( ! exists $uniq_hash{uc($f)} ) {
      $uniq_hash{uc($f)} = '';
    } 
  }
  
  return (keys %uniq_hash);
}


# -----------------------------------------------------------------------------
#
# Arguments:
#   List A (reference)
#   List B (reference)
#
# Returns list composed of all unique elements in A and B

sub list_uniq($)
{
  my ($listref_a) = @_;
  my @dummy = ();
  
  return list_union($listref_a, \@dummy);
}


# -----------------------------------------------------------------------------
#
# Arguments:
#   List A (reference)
#   List B (reference)
#
# Returns list composed of all elements in both A and B

sub list_intersect ($$)
{
  my ($listref_a, $listref_b) = @_;
  my @list;
  my %hash;

  map { $hash{uc($_)} = ''; } @$listref_b;
  return grep { exists $hash{uc($_)} } @$listref_a;

}

=back

=cut

=head1 NOTES / BUGS

This is intended to be used with the I<template_sql> executable.  
I<template_sql> uses the Perl module Text::ScriptTemplate to parse
sql files before passing the sql to sqlplus.

=head1 SEE ALSO

Text::ScriptTemplate

=head1 AUTHOR

Russell Reed - rreed@acxiom.com

=cut

1;


