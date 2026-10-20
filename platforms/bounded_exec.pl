use strict;
use warnings;
use Fcntl qw(O_CREAT O_EXCL O_WRONLY);
use Errno qw(ESRCH);
use POSIX qw(_exit setpgid WNOHANG SIGXFSZ);
use Time::HiRes qw(sleep time);

my ($timeout, $max_bytes, $output, @command) = @ARGV;
die "invalid arguments\n" unless defined $output && @command >= 2 && $command[0] eq '--';
shift @command;
die "invalid limits\n" unless $timeout =~ /^\d+$/ && $timeout >= 1 && $timeout <= 120 && $max_bytes =~ /^\d+$/ && $max_bytes >= 1024 && $max_bytes <= 8388608;

my $output_fh;
unless (sysopen($output_fh, $output, O_CREAT | O_EXCL | O_WRONLY, 0600)) {
    warn "OUTPUT_PATH_REFUSED\n";
    exit 126;
}

my $pid = fork();
unless (defined $pid) {
    close $output_fh;
    warn "CLEANUP_FAILED: fork failed\n";
    exit 126;
}
if ($pid == 0) {
    setpgid(0, 0) == 0 or _exit(126);
    open STDOUT, '>&', $output_fh or _exit(126);
    open STDERR, '>&STDOUT' or _exit(126);
    exec { $command[0] } @command or _exit(127);
}

my $deadline = time() + $timeout;
my $timed_out = 0;
my $oversized = 0;
my $wait_error = 0;
my $leader_done = 0;
my $leader_status = 0;

while (1) {
    my $done = waitpid($pid, WNOHANG);
    if ($done == $pid) {
        $leader_status = $?;
        $leader_done = 1;
        last;
    }
    if ($done == -1) {
        $wait_error = 1;
        last;
    }
    if (-s $output_fh > $max_bytes) { $oversized = 1; last; }
    if (time() >= $deadline) { $timed_out = 1; last; }
    sleep 0.05;
}

# The leader can write and exit between polls; always enforce the final size.
if (!$oversized && -s $output_fh > $max_bytes) {
    $oversized = 1;
}
if ($leader_done && (($leader_status & 127) == SIGXFSZ)) {
    $oversized = 1;
}

my $cleanup_ok = 1;
my $unexpected_residual = 0;
if ($wait_error || $timed_out || $oversized) {
    $cleanup_ok = stop_process_group($pid, \$leader_done, \$leader_status);
    if (!$leader_done) {
        $leader_done = reap_leader_bounded($pid, 2, \$leader_status);
    }
    if (!$leader_done) {
        kill 'KILL', $pid;
        $cleanup_ok = 0;
    }
    if (process_group_running($pid)) {
        $cleanup_ok = 0;
    }
} elsif ($leader_done && process_group_running($pid)) {
    # A successful leader may leave background work that still writes to the
    # evidence file. Stop it, verify the group is gone, and never report success.
    $unexpected_residual = 1;
    $cleanup_ok = stop_process_group($pid, \$leader_done, \$leader_status);
}

if (!$cleanup_ok) {
    warn "CLEANUP_FAILED\n";
    exit 126;
}

if ($wait_error) {
    warn "CLEANUP_FAILED: waitpid failed\n";
    exit 126;
}

if (!$leader_done) {
    warn "CLEANUP_FAILED: process did not exit after termination\n";
    exit 126;
}

if ($timed_out) {
    unless (write_marker($output_fh, $output, "COLLECTION_TIMEOUT\n")) {
        warn "CLEANUP_FAILED: cannot write timeout marker\n";
        exit 126;
    }
    exit 124;
}
if ($oversized) {
    unless (write_marker($output_fh, $output, "OUTPUT_LIMIT_EXCEEDED\n")) {
        warn "CLEANUP_FAILED: cannot write output-limit marker\n";
        exit 126;
    }
    exit 75;
}
if ($unexpected_residual) {
    unless (write_marker($output_fh, $output, "UNEXPECTED_RESIDUAL_PROCESS_TREE\n")) {
        warn "CLEANUP_FAILED: cannot write residual-process marker\n";
    }
    exit 126;
}

exit($leader_status == -1 ? 126 : ($leader_status & 127) ? 128 + ($leader_status & 127) : ($leader_status >> 8));

sub process_group_running {
    my ($pgid) = @_;
    my $count = kill(0, -$pgid);
    return 1 if $count;
    return $! == ESRCH ? 0 : 1;
}

sub stop_process_group {
    my ($pgid, $leader_done_ref, $leader_status_ref) = @_;
    return 1 unless process_group_running($pgid);

    kill 'TERM', -$pgid;
    my $term_deadline = time() + 1;
    while (time() < $term_deadline) {
        observe_leader($pgid, $leader_done_ref, $leader_status_ref);
        return 1 unless process_group_running($pgid);
        sleep 0.05;
    }

    kill 'KILL', -$pgid;
    my $kill_deadline = time() + 1;
    while (time() < $kill_deadline) {
        observe_leader($pgid, $leader_done_ref, $leader_status_ref);
        return 1 unless process_group_running($pgid);
        sleep 0.05;
    }
    return process_group_running($pgid) ? 0 : 1;
}

sub observe_leader {
    my ($child, $leader_done_ref, $status_ref) = @_;
    return 1 if $$leader_done_ref;
    my $done = waitpid($child, WNOHANG);
    if ($done == $child) {
        $$status_ref = $?;
        $$leader_done_ref = 1;
        return 1;
    }
    return $done == -1 ? -1 : 0;
}

sub reap_leader_bounded {
    my ($child, $seconds, $status_ref) = @_;
    my $reap_deadline = time() + $seconds;
    while (time() < $reap_deadline) {
        my $done = waitpid($child, WNOHANG);
        if ($done == $child) {
            $$status_ref = $?;
            return 1;
        }
        return 0 if $done == -1;
        sleep 0.05;
    }
    return 0;
}

sub write_marker {
    my ($fh, $path, $text) = @_;
    my @owned = stat($fh);
    my @current = lstat($path);
    return 0 unless @owned && @current && !-l $path;
    return 0 unless $owned[0] == $current[0] && $owned[1] == $current[1];
    return 0 unless truncate($fh, 0);
    return 0 unless seek($fh, 0, 0);
    print {$fh} $text or return 0;
    return 1;
}
