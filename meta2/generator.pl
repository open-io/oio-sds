#!/usr/bin/perl

use strict;
use warnings;
use POSIX;
use Template;

my $OUTDIR = undef;
my $MODULE = undef;
my $PREFIX = undef;
my $TPLDIR = undef;

use Getopt::Long;
my $result = GetOptions(
	"module=s" => \$MODULE,
	"prefix=s" => \$PREFIX,
	"tpldir=s" => \$TPLDIR,
	"outdir=s" => \$OUTDIR,
);

sub usage {
	my $exit_code = 0;
	if (@_) {
		print STDERR "Error : ",@_,"\n";
		$exit_code = 1;
	}
	print STDERR "\n";
	print STDERR "Usage : ".$0." OPTIONS... TEMPLATE\n";
	print STDERR "Valid OPTIONS fields:\n";
	print STDERR "\t--tpldir=<DIR>    : the directory to read the template files from (default=".POSIX::getcwd().")\n";
	print STDERR "\t--outdir=<DIR>    : where to write the output files (default=.)\n";
	print STDERR "\t--module=<MODULE> : MANDATORY!!!\n";
	print STDERR "\t--prefix=<PREFIX> : specify a different function prefix (default=<MODULE>)\n";
	print STDERR "Valid TEMPLATE values:\n";
	print STDERR "\tmodule : generates a gridd module\n";
	print STDERR "\tremote : generates the <MODULE>_remote API\n";
	print STDERR "Notes:\n";
	print STDERR "\t* At least one TEMPLATE value is necessary\n";
	print STDERR "\t* At least --module is required, and it will be used in the prefix\n";
	print STDERR "\n";
	exit $exit_code;
}

if (not $MODULE) {
	usage("Please provide a module name!");
}

$PREFIX = "$MODULE" unless $PREFIX;
$TPLDIR = "./templates" unless $TPLDIR;
$OUTDIR = POSIX::getcwd() unless $OUTDIR;

my $serializer_index = 1;

our $SERIALIZE_STRUCT = $serializer_index++;
our $SERIALIZE_ARRAY = $serializer_index++;
our $SERIALIZE_POINTER = $serializer_index++;
our $SERIALIZE_STRING = $serializer_index++;
our $SERIALIZE_INTEGER = $serializer_index++;
our $SERIALIZE_LIST_OF_STRINGS = $serializer_index++;
our $SERIALIZE_LIST_OF_SERVICES = $serializer_index++;
our $SERIALIZE_LIST_OF_ADDRESSES = $serializer_index++;
our $SERIALIZE_LIST_OF_CHUNKINFO = $serializer_index++;
our $SERIALIZE_LIST_OF_PATHINFO = $serializer_index++;
our $SERIALIZE_LIST_OF_CONTAINER_EVENT = $serializer_index++;
our $SERIALIZE_LIST_OF_META2_PROPERTY = $serializer_index++;
our $SERIALIZE_LIST_OF_RAWCONTENT_V2 = $serializer_index++;

my @functions = ();

push @functions, {
	'name' => 'service_add_contents',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
		},
	],
	'return' => {
		'type'             => 'struct service_info_s*',
		'serializer'       => $SERIALIZE_LIST_OF_SERVICES,
		'message_location' => 'body',
		'singleton'        => 1,
	},
};

push @functions, {
	'name' => 'service_add_spares',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
		},
	],
	'return' => {
		'type'             => 'struct service_info_s*',
		'serializer'       => $SERIALIZE_LIST_OF_SERVICES,
		'message_location' =>'body',
		'singleton'        => 1,
	},
};

push @functions, {
	'name' => 'service_get_content_service',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'             => 'addr_info_t*',
		'serializer'       => $SERIALIZE_LIST_OF_ADDRESSES,
		'message_location' => 'body',
		'singleton'        => 1,
	},
};

push @functions, {
	'name' => 'service_get_all_used',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'             => 'GSList*',
		'serializer'       => $SERIALIZE_LIST_OF_ADDRESSES,
		'message_location' => 'body',
		'is_out'           => 1,
	},
};

push @functions, {
	'name' => 'service_commit_contents',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
			'is_out'           => 1,
			'on_error'         => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'service_rollback_contents',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
			'is_out'           => 1,
			'on_error'         => 1,
		},
	],
	'return' => {
		'type'=>'status_t'
	},
};

push @functions, {
	'name' => 'service_delete_contents',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
			'is_out'=>1,
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_ADDRESSES,
			'message_location' => 'header',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t'
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_SLAVE_ALLOWED',
};

push @functions, {
	'name' => 'service_flush',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_ADDRESSES,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_SLAVE_ALLOWED',
};

push @functions, {
	'name' => 'container_services_get_all_used',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' =>'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_SERVICES,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'container_services_get_available',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'=>'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_SERVICES,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name'      => 'set_content_property',
	'real_name' => 'set_content_property_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_WORM_ALLOWED|REQ_DROP_EVENTS',
};

push @functions, {
	'name' => 'get_content_property',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_all_content_properties',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
			'is_out'=>1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name'      => 'remove_content_property',
	'real_name' => 'remove_content_property_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_WORM_ALLOWED|REQ_DROP_EVENTS',
};

push @functions, {
	'name'      => 'set_container_global_property',
	'real_name' => 'set_container_global_property_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_WORM_ALLOWED|REQ_DROP_EVENTS',
};

push @functions, {
	'name'      => 'set_container_property',
	'real_name' => 'set_container_property_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_WORM_ALLOWED|REQ_DROP_EVENTS',
};

push @functions, {
	# Does not generate an event but is allowed in SLAVE mode
	'name'      => 'replicate_set_container_property',
	'real_name' => 'set_container_property',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
	'v1' => 0,
};

push @functions, {
	'name' => 'get_container_property',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_all_container_properties',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_STRINGS,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_container_properties',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_META2_PROPERTY,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name'      => 'remove_container_property',
	'real_name' => 'remove_container_property_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type' => 'status_t',
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_WORM_ALLOWED|REQ_DROP_EVENTS',
};

push @functions, {
	# Does not generate an event but is allowed in SLAVE mode
	'name'      => 'replicate_remove_container_property',
	'real_name' => 'remove_container_property',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type' => 'status_t',
	},
	'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
	'v1' => 0,
};

push @functions, {
	'name'      => 'add_container_event',
	'real_name' => 'add_container_event_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'container_event_t*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'singleton'        => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
 	         # Does not generate an event but is allowed in SLAVE mode
 	         'name'      => 'replicate_add_container_event',
 	         'real_name' => 'add_full_container_event',
 	         'args' => [
 	                 {
 	                         'type'             => 'container_id_t',
 	                         'serializer'       => $SERIALIZE_ARRAY,
 	                         'message_location' => 'header',
 	                 },
 	                 {
 	                         'type'             => 'container_event_t*',
 	                         'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
 	                         'message_location' => 'body',
 	                         'singleton'        => 1,
 	                 },
 	         ],
 	         'return' => {
 	                 'type'=>'status_t',
 	         },
 	         'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
 	         'v1' => 0,
 	 };

push @functions, {
	'name' => 'get_container_event_rowid',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
			'is_out'           => 1,
		},
		{
			'type'             => 'container_event_t*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'singleton'        => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'get_container_events_by_timestamp',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_container_events',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_container_events_since',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header'},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_container_events_up_to',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_last_container_events',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'list_all_container_events',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t'
	},
};

push @functions, {
	'name' 	    => 'remove_container_event_by_rowid',
	'real_name' => 'remove_container_event_by_rowid_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},

	#'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
};

push @functions, {
	'name' => 'remove_container_event_by_event',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'container_event_t*',
			'serializer'       => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
			'message_location' => 'body',
			'singleton'        => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},

	#'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
};

push @functions, {
        # Does not generate an event but is allowed in SLAVE mode
        'name'      => 'replicate_remove_container_event',
        'real_name' => 'remove_container_event_by_rowid',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
         'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
         'v1' => 0,
};

push @functions, {
	'name' => 'remove_all_container_events',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},

	#'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
};

push @functions, {
	'name' => 'stat_content_v2',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'meta2_raw_content_v2_t*',
			'serializer'       => $SERIALIZE_LIST_OF_RAWCONTENT_V2,
			'message_location' => 'body',
			'singleton'        => 1,
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
};

push @functions, {
	'name' => 'replicate_content_v2',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'meta2_raw_content_v2_t*',
			'serializer'       => $SERIALIZE_LIST_OF_RAWCONTENT_V2,
			'message_location' => 'body',
			'singleton'        => 1,
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_SLAVE_ALLOWED|REQ_WORM_ALLOWED',
};

push @functions, {
	'name' => 'container_enable',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_ALWAYS',
};

push @functions, {
	'name' => 'container_disable',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_ALWAYS',
};

push @functions, {
	'name' => 'container_freeze',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_ALWAYS',
};

push @functions, {
	'name' => 'container_disable_disabled',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t',
	},
	'flags' => 'REQ_ALWAYS',
};

push @functions, {
	'name' => 'list_content_specif',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'GSList*',
			'serializer'       => $SERIALIZE_LIST_OF_PATHINFO,
			'message_location' => 'body',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t'
	},
};

push @functions, {
	'name' => 'get_container_size',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gint64',
			'serializer'       => $SERIALIZE_INTEGER,
			'message_location' => 'header',
			'is_out'           => 1,
		},
	],
	'return' => {
		'type'=>'status_t'
	},
};

push @functions, {
	'name' => 'modify_metadatausr',
	'real_name' => 'modify_metadatausr_wrapper',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t'
	},
	'flags' => 'REQ_MASTER_ALLOWED|REQ_WORM_ALLOWED|REQ_DROP_EVENTS',
};

push @functions, {
	'name' => 'modify_metadatasys',
	'args' => [
		{
			'type'             => 'container_id_t',
			'serializer'       => $SERIALIZE_ARRAY,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
		{
			'type'             => 'gchar*',
			'serializer'       => $SERIALIZE_STRING,
			'message_location' => 'header',
		},
	],
	'return' => {
		'type'=>'status_t'
	},
};

sub generate_file {
	my $template = shift;
	my $output = shift;
	my $template_doc = shift;

	my $path = "$OUTDIR/$output";
	my $vars = {
		'module_name' => lc($MODULE),
		'module_functions' => \@functions,
	};

	print STDERR "Generating '$path' from '$template_doc'\n";

	open(OUT_FD,">$path") or die "Failed to open $path\n";
	$template->process($template_doc, $vars, \*OUT_FD) || die "Failed to parse $template_doc in $path : ".$template->error()."\n";
	close(OUT_FD);

	#`indent $path`;
}

sub expand_field_configuration {
	my $field = shift;
	$field->{'is_list'} = 0;
	if (exists ($field->{'serializer'})) {
		if ($field->{'serializer'} eq $SERIALIZE_LIST_OF_STRINGS) {
			$field->{'marshaller'} = 'strings_marshall_gba';
			$field->{'unmarshaller'} = 'strings_unmarshall';
			$field->{'cleaner'} = 'g_free1';
			$field->{'body_manager'} = 'strings_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_SERVICES) {
			$field->{'marshaller'} = 'service_info_marshall_gba';
			$field->{'unmarshaller'} = 'service_info_unmarshall';
			$field->{'cleaner'} = 'service_info_gclean';
			$field->{'body_manager'} = 'service_info_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_ADDRESSES) {
			$field->{'marshaller'} = 'addr_info_marshall_gba';
			$field->{'unmarshaller'} = 'addr_info_unmarshall';
			$field->{'cleaner'} = 'addr_info_gclean';
			$field->{'body_manager'} = 'addr_info_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_CHUNKINFO) {
			$field->{'marshaller'} = 'chunk_info_marshall_gba';
			$field->{'unmarshaller'} = 'chunk_info_unmarshall';
			$field->{'cleaner'} = 'chunk_info_gclean';
			$field->{'body_manager'} = 'chunk_info_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_PATHINFO) {
			$field->{'marshaller'} = 'path_info_marshall_gba';
			$field->{'unmarshaller'} = 'path_info_unmarshall';
			$field->{'cleaner'} = 'path_info_gclean';
			$field->{'body_manager'} = 'path_info_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_CONTAINER_EVENT) {
			$field->{'marshaller'} = 'container_event_marshall_gba';
			$field->{'unmarshaller'} = 'container_event_unmarshall';
			$field->{'cleaner'} = 'container_event_gclean';
			$field->{'body_manager'} = 'container_event_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_META2_PROPERTY) {
			$field->{'marshaller'} = 'meta2_property_marshall_gba';
			$field->{'unmarshaller'} = 'meta2_property_unmarshall';
			$field->{'cleaner'} = 'meta2_property_gclean';
			$field->{'body_manager'} = 'meta2_property_concat';
			$field->{'is_list'} = 1;
		} elsif ($field->{'serializer'} eq $SERIALIZE_LIST_OF_RAWCONTENT_V2) {
			$field->{'marshaller'} = 'meta2_raw_content_v2_marshall_gba';
			$field->{'unmarshaller'} = 'meta2_raw_content_v2_unmarshall';
			$field->{'cleaner'} = 'meta2_raw_content_v2_gclean';
			$field->{'body_manager'} = 'meta2_raw_content_v2_concat';
			$field->{'is_list'} = 1;
		}
	}
	return $field;
}

# Normalization
foreach my $f (@functions) {
	my $order = 0;
	$f->{'in_args'} = [];
	$f->{'out_args'} = [];
	$f->{'prefix'} = lc($PREFIX);
	$f->{'request_name'} = uc($MODULE.'_'.$f->{'name'});
	$f->{'real_name'} = "".$f->{'name'} unless defined $f->{'real_name'};
	
	$f->{'flags'} = 'REQ_ALWAYS' unless exists($f->{'flags'});
	$f->{'v1'} = 1 unless defined $f->{'v1'};
	$f->{'v2'} = 1 unless defined $f->{'v2'};

	foreach my $arg (@{$f->{'args'}}) {
		$arg->{'local_name'} = "var_$order";
		$arg->{'message_name'} = "field_$order";

		if ($arg->{'is_out'}) {
			push @{$f->{'out_args'}}, $arg;
		} else {
			push @{$f->{'in_args'}}, $arg;
		}
		$order ++;
	}

	if (not exists($f->{'return'})) {
		$f->{'return'} = { 'type' => 'void' };
	} else {
		$f->{'return'}->{'local_name'} = 'result';
		$f->{'return'}->{'message_name'} = 'result';
		delete $f->{'return'}->{'is_out'};
	}

	$f->{'has_out'} = exists($f->{'return'}->{'serializer'}) || +@{$f->{'out_args'}};

	foreach my $field (@{$f->{'args'}}) {
		expand_field_configuration($field);
	}
	expand_field_configuration($f->{'return'});
}

my %config_template = (
	AUTO_RESET => 0,
	START_TAG => '{{',
	END_TAG => '}}',
	INCLUDE_PATH => $TPLDIR,
	INTERPOLATE  => 1,
	CONSTANTS => {
		SERIALIZE_STRUCT => $SERIALIZE_STRUCT,
		SERIALIZE_ARRAY => $SERIALIZE_ARRAY,
		SERIALIZE_POINTER => $SERIALIZE_POINTER,
		SERIALIZE_STRING => $SERIALIZE_STRING,
		SERIALIZE_INTEGER => $SERIALIZE_INTEGER,
		SERIALIZE_LIST_OF_STRINGS => $SERIALIZE_LIST_OF_STRINGS,
		SERIALIZE_LIST_OF_SERVICES => $SERIALIZE_LIST_OF_SERVICES,
		SERIALIZE_LIST_OF_ADDRESSES => $SERIALIZE_LIST_OF_ADDRESSES,
		SERIALIZE_LIST_OF_CHUNKINFO => $SERIALIZE_LIST_OF_CHUNKINFO,
		SERIALIZE_LIST_OF_PATHINFO => $SERIALIZE_LIST_OF_PATHINFO,
		SERIALIZE_LIST_OF_CONTAINER_EVENT => $SERIALIZE_LIST_OF_CONTAINER_EVENT,
		SERIALIZE_LIST_OF_CONTAINER_EVENT => $SERIALIZE_LIST_OF_META2_PROPERTY,
	},
	FILTERS => {
		'uc' => sub { return uc($_[0]); },
		'lc' => sub { return lc($_[0]); },
	},
);

my $tt = Template->new({ %config_template, }) || die "$Template::ERROR\n";

# We load the common blocks used in several files
$tt->process('common.tpl', { 'module_name' => lc($MODULE) }) || die "Failed to parse the common ".$tt->error()."\n";

if (not @ARGV) {
	usage("Please provide an action to be performed!");
}

while (my $WHAT = shift @ARGV) {
	$WHAT = lc($WHAT);

	foreach my $f (@functions) {
		foreach my $a (@{$f->{'args'}}) {
			if ($a->{'type'} eq 'gchar*') {
				$a->{'type_decl'} = 'const gchar*';
			}
			elsif ($a->{'type'} eq 'char*') {
				$a->{'type_decl'} = 'const char*';
			}
			elsif ($a->{'type'} eq 'container_id_t') {
				$a->{'type_decl'} = 'const container_id_t';
			}
			else {
				$a->{'type_decl'} = $a->{'type'};
			}
		}
	}

	if ($WHAT eq 'module') {
		generate_file($tt,"msg_${MODULE}.c",'module.tpl');
		generate_file($tt,"autogenerated_handlers_${MODULE}.c",'handlers.tpl');
	}

	if ($WHAT eq 'remote') {
		generate_file($tt,"${MODULE}_remote.c",'remote.c.tpl');
		generate_file($tt,"${MODULE}_remote.h",'remote.h.tpl');
	}
}

exit 0;
