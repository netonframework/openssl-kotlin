#!/usr/bin/env perl
use strict;
use warnings;
use Fcntl qw(:flock F_SETFD);

my $path = shift @ARGV or die "Usage: with-build-lock.pl <lock file> <command> [args]\n";
@ARGV or die "Missing command\n";
open(my $lock, '>>', $path) or die "open $path: $!\n";
flock($lock, LOCK_EX) or die "lock $path: $!\n";
# Keep the kernel lock across exec, including cancellation of the invoking Gradle process.
fcntl($lock, F_SETFD, 0) or die "inherit $path: $!\n";
exec @ARGV;
die "exec $ARGV[0]: $!\n";
