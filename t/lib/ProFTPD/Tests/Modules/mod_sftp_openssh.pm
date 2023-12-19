package ProFTPD::Tests::Modules::mod_sftp_openssh;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use File::Copy;
use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;
use IPC::Open3;
use POSIX qw(:fcntl_h);
use Socket;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :features :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  openssh_auth_publickey_rsa => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_unsupported_key_type => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_bad_key_data => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_without_comment => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_empty_file => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_blank_file => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_comments_file => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  # OpenSSH entries with options

  openssh_auth_publickey_rsa_with_option_command => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_rsa_with_option_from => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_rsa_with_option_no_touch_required => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

  openssh_auth_publickey_rsa_with_option_verify_required => {
    order => ++$order,
    test_class => [qw(forking ssh2)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Net-SSH2
  #  Net-SSH2-SFTP

  my $required = [qw(
    Net::SSH2
    Net::SSH2::SFTP
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  return testsuite_get_runnable_tests($TESTS);
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  unless (chmod(0400, $rsa_host_key)) {
    die("Can't set perms on $rsa_host_key: $!");
  }
}

sub openssh_auth_publickey_rsa {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_pub_key, $authorized_keys)) {
    die("Can't copy $rsa_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_unsupported_key_type {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/unsupported_key_type.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("RSA publickey authentication succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_bad_key_data {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_bad_key.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("RSA publickey authentication succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_without_comment {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key_without_comment.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($rsa_pub_key, $authorized_keys)) {
    die("Can't copy $rsa_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_empty_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use a test comprised of an empty file.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/empty.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("RSA publickey authentication succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_blank_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use a test comprised of only blank lines.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/blank.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("RSA publickey authentication succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_comments_file {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use a test comprised of only commented lines.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/comments.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      if ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        die("RSA publickey authentication succeeded unexpectedly");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_rsa_with_option_command {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use an entry using the unsupported "command" option.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key_with_option_command.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_rsa_with_option_from {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use an entry using the unsupported "from" option.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key_with_option_from.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_rsa_with_option_no_touch_required {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use an entry using the supported "no-touch-required" option.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key_with_option_no_touch_required.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /supported key options parsed: 1/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub openssh_auth_publickey_rsa_with_option_verify_required {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'sftp');

  my $rsa_host_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/ssh_host_rsa_key');

  my $rsa_priv_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key');
  my $rsa_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key.pub');

  # Use an entry using the supported "verify-required" option.
  my $test_pub_key = File::Spec->rel2abs('t/etc/modules/mod_sftp_openssh/test_rsa_key_with_option_verify_required.pub');

  my $authorized_keys = File::Spec->rel2abs("$tmpdir/.authorized_keys");
  unless (copy($test_pub_key, $authorized_keys)) {
    die("Can't copy $test_pub_key to $authorized_keys: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'sftp.openssh:30 ssh2:30',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPAuthorizedUserKeys openssh:~/.authorized_keys",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow for server startup
      sleep(2);

      my $ssh2 = Net::SSH2->new();
      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_publickey($setup->{user}, $rsa_pub_key,
          $rsa_priv_key)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("RSA publickey authentication failed: [$err_name] ($err_code) $err_str");
      }

      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $ok = 0;

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }

        if ($line =~ /supported key options parsed: 1/) {
          $ok = 1;
          last;
        }
      }

      close($fh);
      $self->assert($ok, test_msg("Did not see expected TraceLog message"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

1;
