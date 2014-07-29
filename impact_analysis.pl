#!/usr/bin/perl

use Data::Dumper;
use File::Find;

use warnings;
use strict;

sub err_exit;
sub htmlise;
sub seconds_to_time;

my $status_file = "/var/log/nagios3/nagios.log";
my $configs = "/etc/nagios3/conf.d";
my $impact_host_map = "/etc/nagios3/etc/impact_host_map.cfg";
my $impact_service_map = "/etc/nagios3/etc/impact_service_map.cfg";
my $time = time;
my $debug = 0;
my $file;
my $line;
my %hosts;
my %s_list;

my $arg_i = 0;
while ( $arg_i < scalar( @ARGV ) )
{
	my $arg = $ARGV[ $arg_i ];
	$arg_i++;

# all checks for flags without a value go here
	if ( $arg eq "-h" or $arg eq "--help" )
	{
		usage();
		exit;
	}
	next if ( $arg_i >= scalar( @ARGV ) ); # no more parameters, so quit. This protects array overflow below
# All checks for flags with 1 parameter go here
	if ( $arg eq "-s" or $arg eq "--status_file")
	{
		$arg = $ARGV[ $arg_i ];
		$status_file = $arg if ( $arg );
	}
	elsif( $arg eq "-c" or $arg eq "--config_dir" )
	{
		$arg = $ARGV[ $arg_i ];
		$configs = $arg if ( $arg );
	}
	elsif( $arg eq "-hm" or $arg eq "--host_map" )
	{
		$arg = $ARGV[ $arg_i ];
		$impact_host_map = $arg if ( $arg );
	}
	elsif( $arg eq "-sm" or $arg eq "--service_map" )
	{
		$arg = $ARGV[ $arg_i ];
		$impact_service_map = $arg if ( $arg );
	}

	# Any checks for flags with multiple parameters go here
}

my $localtime=localtime($time);

find( \&read_conf, $configs );
sub read_conf
{
	#Build a list of all internal monitored hosts
	my $file = $_;
	return if ( -d $file ); # skip this if its a directory, we are only interested in files
	return if ( $file !~ /.cfg$/ ); #we only want the cfg files

	open (CONFFILE, "< $file") or die "Cannot open $file: $!";
	while ($line = <CONFFILE>) 
	{
		if ($line =~/^(\s*\#|\s*$)/) { next; }
		if ($line =~/host_name\s*(.+)/) 
		{ 
			$hosts{$1}{state} = 0;      #0 is up
			$hosts{$1}{impact} = 1;      #impact, 1 - 10, 1 unless told otherwise
		}
	}
	close (CONFFILE);
}
#closedir (DIR);

#Store the contents of $impact_host_map in our hash
open (HOST_IMPACT, $impact_host_map) || err_exit "cannot open $impact_host_map\: $!";
while ($line=<HOST_IMPACT>) 
{
	next if ($line =~/^\s*(\#.*)?$/); 	#Ignore blank lines and comment lines
	$line =~s/\#.*//;			#Ignore comments
	my ($host,$impact,$message) = split(/\,/,$line,3);
	$hosts{$host}{impact} = $impact;
	$hosts{$host}{message} = $message;
}
close (HOST_IMPACT);

#Store the contents of $impact_service_map in our service list hash
open (S_LIST, $impact_service_map) || err_exit "cannot open $impact_service_map\: $!";
while ($line=<S_LIST>) 
{
	next if ($line =~/^\s*(\#.*)?$/); 	#Ignore blank lines and comment lines
	$line =~s/\#.*//;			#Ignore comments
	my ($service,$message) = split(/\,/,$line,2);
	$s_list{$service} = $message;
}
close (HOST_IMPACT);

open (STATUS, $status_file) || err_exit "Cannot open status file, $status_file : $!";

while ($line = <STATUS>) 
{
	if ($line =~/^\[\d+\] HOST .*?: (.*)$/) 
	{
		my @values = split( /;/, $1 );
		my $host = shift @values;
		my $state = shift @values;
		my $description = join( ';', @values );
		if (!exists($hosts{$host})) { next; } #Customer or other
		$hosts{$host}{state} = $state; # if ($state eq "UP" || $state eq "PENDING");
		$hosts{$host}{description} = $description;
	}
	elsif ($line =~/^\[\d+\] SERVICE ALERT: (.*)$/)
	{
		my @values = split( /;/, $1 );
		my $host = shift @values;
		my $service = shift @values;
		my $state = shift @values;
		my $status = shift @values;
		my $count = shift @values;
		my $description = join( ';', @values ) || "";
		if (!exists($hosts{$host})) { next; }

		$hosts{$host}{service}{$service}{state} = $state;
		$hosts{$host}{service}{$service}{status} = $status;
		$hosts{$host}{service}{$service}{description} = $description;
	}
	elsif ($line =~/^\[\d+\] CURRENT SERVICE STATE: (.*)$/) { #A split is nicer than parsing up here.
		my @values = split( /;/, $1 );
		my $host = shift @values;
		my $service = shift @values;
		my $state = shift @values;
		my $status = shift @values;
		my $count = shift @values;
		my $description = join( ';', @values ) || "";
		if (!exists($hosts{$host})) { next; }
		$hosts{$host}{service}{$service}{state} = $state;
		$hosts{$host}{service}{$service}{status} = $status;
		$hosts{$host}{service}{$service}{description} = $description;
	}
}
#print Dumper( \%hosts );

print << "END";
Content-Type: text/html

<html>
<HEAD>
<TITLE>Impact Analysis</TITLE>
<meta name="Pragma" content="no-cache" />
<meta http-equiv="Expires" content="0" />
<meta http-equiv="Refresh" content="30" />
<style><!--
body,td,a,p,.h{font-family:verdana; font-size: x-small;}
//-->
</style>
</HEAD>
<BODY>
<font face="Verdana" size="1">
<B><font="Verdana" size=1"><p align=right>$localtime</p></font></b>
<H1><CENTER>Impact Analysis</CENTER></H1>
END

foreach my $host (keys %hosts) 
{
	# if host state isn't set or the host is "UP" and there are no services in a critical state then ignore this host
	my %services;
	%services = %{$hosts{$host}{service}} if ( $hosts{$host}{service} );
	# check all the services and see if any are CRITICAL
	my @critical_services = grep 
							{ 
								my $s_key = $_; 
								my $state = $services{$s_key}{state};
								my $status = $services{$s_key}{status};
								$state and $state eq "CRITICAL" and $status eq "HARD";
							} keys %services;
	# skip this host if it is UP and there are no critical services
	next if ( (not $hosts{$host}{state} or $hosts{$host}{state} eq "UP" ) and scalar( @critical_services ) == 0 ); 

	print "<hr>\nImpact: $hosts{$host}{impact}, host: <b>$host</b>";
	print " state: ";
	if ($hosts{$host}{state}) 
	{
		print " <font color=#AA4444>$hosts{$host}{state}</font>";
#    print "<td>Last checked ".localtime($hosts{$host}{last_check})."</td>\n";
	} 
	else 
	{
		print " <font color=#44AA44>UP</font><br>\n";
	}
	if ( $hosts{$host}{description} )
	{
		print " Description: $hosts{$host}{description}<br>\n";
	}
	if (exists($hosts{$host}{message})) 
	{
		print " &nbsp;Responsible for $hosts{$host}{message}<br>\n";
	}
	foreach my $service ( @critical_services )
	{
		print "<table><tr><td><li></td><td>$service ";
		if ($hosts{$host}{service}{$service}{state} ne "OK") 
		{
			print "<font color=#AA4444>$hosts{$host}{service}{$service}{state}</font>";
		} 
		else 
		{
			print "<font color=#44AA44>$hosts{$host}{service}{$service}{state}</font>";
		}
		print "</tr><tr><td></td><td>&nbsp;$hosts{$host}{service}{$service}{description}</td></tr>\n";
#This service needs to be clasified so a short service description can be added.
		if ($service =~/load|CPU/i) { print "<tr><td></td><td>&nbsp;$s_list{load}</tr>\n"; } 
		elsif ($service =~/disk/i) { print "<tr><td></td><td>&nbsp;$s_list{disk}</td></tr>\n"; } 
		elsif ($service =~/mailq/i) { print "<tr><td></td><td>&nbsp;$s_list{mailq}</td></tr>\n"; } 
		elsif ($service =~/bgp/i) { print "<tr><td></td><td>&nbsp;$s_list{BGP}</td></tr>\n"; } 
		elsif ($service =~/pop3/i) { print "<tr><td></td><td>&nbsp;$s_list{POP3}</td></tr>\n"; } 
		elsif ($service =~/imap/i) { print "<tr><td></td><td>&nbsp;$s_list{IMAP}</td></tr>\n"; } 
		elsif ($service =~/smtp/i) { print "<tr><td></td><td>&nbsp;$s_list{SMTP}</td></tr>\n"; } 
		elsif ($service =~/ssh/i) { print "<tr><td></td><td>&nbsp;$s_list{SSH}</td></tr>\n"; } 
		elsif ($service =~/dns/i) { print "<tr><td></td><td>&nbsp;$s_list{DNS}</td></tr>\n"; } 
		elsif ($service =~/proxy/i) { print "<tr><td></td><td>&nbsp;$s_list{PROXY}</td></tr>\n"; } 
		elsif ($service =~/ftp/i) { print "<tr><td></td><td>&nbsp;$s_list{FTP}</td></tr>\n"; } 
		elsif ($service =~/http/i) { print "<tr><td></td><td>&nbsp;$s_list{HTTP}</td></tr>\n"; } 
		elsif ($service =~/radius/i) { print "<tr><td></td><td>&nbsp;$s_list{radius}</td></tr>\n"; } 
		elsif ($service =~/mysql/i) { print "<tr><td></td><td>&nbsp;$s_list{mysql}</td></tr>\n"; } 
		elsif ($service =~/postgresql/i) { print "<tr><td></td><td>&nbsp;$s_list{postgresql}</td></tr>\n";  
		}
		print "</td></tr></table>\n";
	}
}

print << 'END';
<hr>
</font>
</BODY>
</HTML>
END

sub seconds_to_time 
{
	my $secs = shift;
	my $msg = "";
	my $mod = "";

	if ($secs > 604800) 
	{ 
		$msg.= sprintf("%d Week(s),",int($secs/604800)); #Weeks
		$mod = " ";
		$secs-= int($secs/604800)*604800;
	}
	if ($secs > 86400) 
	{
		$msg.= sprintf("$mod%d Days,",int($secs/86400)); #Days
		$mod = " ";
		$secs-= int($secs/86400)*86400;
	}
	$msg.= sprintf("$mod%02d:",int($secs/3600)); #Hours
	$secs-= int($secs/3600)*3600;
	$msg.= sprintf("%02d:",int($secs/60)); #Hours
	$secs-= int($secs/60)*60;
	$msg.= sprintf("%02d",$secs);
	return $msg;
}
sub err_exit 
{
	my $msg = shift;
	print "<h1><font face=Verdana size=1 color=#AA4444>$msg</font></h1>\n<hl>\n</body>\n</html>\n";
	die;
}
sub htmlise 
{
	my $string = shift;
	my $char;
	my $return="";

	chomp $string;

	while ($string=~/^(.)(.*)$/) 
	{
		$char = $1;
		$string = $2;
		if ($char !~/\w/) 
		{
			$char = "%".sprintf("%x",unpack("C",$char));
		}
		$return.=$char;
	}
	return $return;
}

sub usage
{
	print <<USAGE;
	$0 [option, ...]
		-h, --help					This help
		-s, --status_file FILE		Default: /var/log/nagios3/nagios.log
		-c, --config_dir DIR		The dir to nagios confs. Default: /etc/nagios3/conf.d
		-hm, --host_map FILE		Default: /etc/nagios3/etc/impact_host_map.cfg
		-sm, --service_map FILE		Default: /etc/nagios3/etc/impact_service_map.cfg
USAGE
}
