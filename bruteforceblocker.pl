#!/usr/bin/perl

# BruteForceBlocker v1.2.3
# - Daniel Gerzo <danger@rulez.sk>

use strict;
use warnings;

use Sys::Syslog;
use Sys::Hostname;
use LWP::UserAgent;
use Net::DNS::Resolver;

$ENV{'PATH'} = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin';
our $cfg;

# this is where configuration file is located
require '/usr/local/etc/bruteforceblocker.conf';

my $work = {
	ipv4		=> '(?:\d{1,3}\.){3}\d{1,3}',	# regexp to match ipv4 address
	ipv6		=> '[\da-fA-F:]+',		# regexp to match ipv6 address
	fqdn		=> '[\da-z\-.]+\.[a-z]{2,4}',	# regexp to match fqdn
	hostname	=> hostname,			# get hostname from Sys::Hostname module
	projectsite	=> 'http://danger.rulez.sk/projects/bruteforceblocker',
};

openlog('BruteForceBlocker', 'pid', 'auth');

if ($cfg->{use_remote}) {
    # load IPs from existing table to the @localIPs array
    open(TABLE, $cfg->{tablefile}) or syslog("notice", "Couldn't open $cfg->{tablefile} for reading");
    while (<TABLE>) {
	push(@{$work->{localIPs}}, $1) if /^($work->{ipv4}|$work->{ipv6})/;
    }
    close(TABLE) or syslog("notice", "Couldn't close $cfg->{tablefile}");

    syslog('notice', 'downloading blacklist from project site') if $cfg->{debug};

    # download the list from project site and load IPs to @remoteIPs array
    if ( my $content = download("$work->{projectsite}/blist.php?mindays=$cfg->{mindays}&mincount=$cfg->{mincount}") ) {
	while( $content =~ /^($work->{ipv4}|$work->{ipv6})/gm ) {
	   push(@{$work->{remoteIPs}}, $1);
	}
    } else {
	syslog('notice', "Can't download IP blacklist from project site") if $cfg->{debug};
    }

    # get IPs that we don't have in local pf table
    my %seen = ();
    @seen{@{$work->{localIPs}}} = () if exists $work->{localIPs};
	
    foreach my $IP (@{$work->{remoteIPs}}) {
	push(@{$work->{newa}}, $IP) unless exists $seen{$IP};
    }

    # add them to the table
    $work->{timea} = scalar(localtime);
    foreach my $IP (@{$work->{newa}}) {
	if (!grep { /$IP/ } @{$cfg->{whitelist}}) {
	    $work->{pool} = $IP . '/32'  if ($IP =~ /\./);  # block whole ipv4 pool
	    $work->{pool} = $IP . '/128' if ($IP =~ /\:/);  # block while ipv6 pool
	    syslog('notice', "adding $IP to the $cfg->{table} table and firewall") if $cfg->{debug};
	    system("echo '$work->{pool}\t\t# added from project site at $work->{timea}' >> $cfg->{tablefile}") == 0 ||
		syslog('notice', "Couldn't add $work->{pool} from project site to $cfg->{tablefile}");
	    system("$cfg->{pfctl} -t $cfg->{table} -T add $work->{pool}") == 0 ||
		syslog('notice', "Couldn't add $work->{pool} to firewall");
	}
    }
    syslog('notice', 'blacklist synchronized with project site') if $cfg->{debug};
}

my %count = ();	# hash used to store total number of failed tries
my %timea = ();	# hash used to store last time when IP was active
my $res   = Net::DNS::Resolver->new;

# the core process

while (<>) {
    if (/.*Failed password.*from ($work->{ipv4}|$work->{ipv6}|$work->{fqdn}) port.*/i ||
	/.*Invalid user.*from ($work->{ipv4}|$work->{ipv6}|$work->{fqdn})$/i ||
	/.*Did not receive identification string from ($work->{ipv4}|$work->{ipv6}|$work->{fqdn})$/i ||
	/.*Bad protocol version identification .* from ($work->{ipv4}|$work->{ipv6}|$work->{fqdn})$/i ||
	/.*User.*from ($work->{ipv4}|$work->{ipv6}|$work->{fqdn}) not allowed because.*/i ) {

	my $IP = $1;
	if ($IP =~ /$work->{fqdn}/i) {
	    foreach my $type (qw(AAAA A)) {
		my $query = $res->search($IP, $type);
		if ($query) {
		    foreach my $rr ($query->answer) {
			block($rr->address);
		    }
		}
	    }
	} else {
	    block($IP);
	}
    }
}

closelog();

sub download {
    my $url = shift or die "Need url!\n";
    # create useragent
    my $ua = LWP::UserAgent->new(
	agent 	=> 'BruteForceBlocker v1.2.3',
	timeout => 10
    );
    # send request
    my $res = $ua->get($url);

    # check the outcome
    if ($res->is_success) {
	return $res->content;
    } else {
	syslog('notice', "Error: " . $res->status_line);
    }
}

sub block {
    my ($IP) = shift or die "Need IP!\n";

    if ($timea{$IP} && ($timea{$IP} < time - $cfg->{timeout})) {
	syslog('notice', "resetting $IP count, since it wasn't active for more than $cfg->{timeout} seconds") if $cfg->{debug};
	delete $count{$IP};
    }
    $timea{$IP} = time;

    # increase the total number of failed attempts
    $count{$IP}++;

    if ($cfg->{debug} && ($count{$IP} < $cfg->{max_attempts}+1)) {
	syslog('notice', "$IP was logged with total count of $count{$IP} failed attempts");
    }

    if ($count{$IP} == $cfg->{max_attempts}+1) {
	syslog('notice', "IP $IP reached maximum number of failed attempts!") if $cfg->{debug};
	if (!grep { /$IP/ } @{$cfg->{whitelist}}) {
	    $work->{pool}  = $IP . '/32'  if ($IP =~ /\./); # block whole ipv4 pool
	    $work->{pool}  = $IP . '/128' if ($IP =~ /\:/); # block while ipv6 pool
	    $work->{timea} = scalar(localtime);

	    syslog('notice', "blocking $work->{pool} in pf table $cfg->{table}.");
	    system("$cfg->{pfctl} -t $cfg->{table} -T add $work->{pool}") == 0 ||
		syslog('notice', "Couldn't add $cfg->{pool} to firewall");
	    system("$cfg->{pfctl} -k $IP") == 0 ||
		syslog('notice', "Couldn't kill all states for $IP");
	    system("echo '$work->{pool}\t\t# $work->{timea}' >> $cfg->{tablefile}") == 0 ||
		syslog('notice', "Could't write $work->{pool} to $cfg->{table}'s table file");

	    # send mail if it is configured
	    if ($cfg->{email} && $cfg->{email} ne '') {
		syslog('notice', "sending email to $cfg->{email}") if $cfg->{debug};
		open(MAIL, "| $cfg->{mail} -s '$work->{hostname}: BruteForceBlocker blocking $work->{pool}' $cfg->{email}");
		print (MAIL "BruteForceBlocker blocking $work->{pool} in pf table $cfg->{table}\n");
		close(MAIL);
	    }
	    ;

	    # report blocked IP if it is enabled
	    if ($cfg->{report}) {
		syslog('notice', "Reporting $IP to BruteForceBlocker project site") if $cfg->{debug};
		download("$work->{projectsite}/report.php?ip=$IP");
	    }
	} else {
	    syslog('notice', "...but $IP is whitelisted, so we will not block it!") if $cfg->{debug};
	}
    }
}
