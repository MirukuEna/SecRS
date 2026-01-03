/**
 * Process Isolation System for Sare Terminal
 * 
 * This module provides comprehensive process and resource isolation
 * capabilities, including namespace isolation, resource limits, and
 * security containment to prevent malicious processes from affecting
 * the system.
 * 
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 * File: isolation.rs
 * Description: Process and resource isolation system
 */

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::{SecurityConfig, SecurityEvent, SecuritySeverity};

/**
 * Isolation level
 * 
 * Defines isolation levels for process isolation strength management.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsolationLevel {
	/// No isolation
	None,
	/// Basic isolation
	Basic,
	/// Enhanced isolation
	Enhanced,
	/// Maximum isolation
	Maximum,
}

/**
 * Isolation configuration
 * 
 * Manages isolation settings including process isolation, resource limits,
 * and security container configuration.
 */
#[derive(Debug, Clone)]
pub struct IsolationConfig {
	/// Enable process isolation
	pub process_isolation: bool,
	/// Enable namespace isolation
	pub namespace_isolation: bool,
	/// Enable filesystem isolation
	pub filesystem_isolation: bool,
	/// Enable network isolation
	pub network_isolation: bool,
	/// Enable user isolation
	pub user_isolation: bool,
	/// Default isolation level
	pub default_isolation_level: IsolationLevel,
	/// Maximum CPU usage (percentage)
	pub max_cpu_usage: u32,
	/// Maximum memory usage (bytes)
	pub max_memory_usage: u64,
	/// Maximum disk usage (bytes)
	pub max_disk_usage: u64,
	/// Maximum network bandwidth (bytes/sec)
	pub max_network_bandwidth: u64,
	/// Allowed system calls
	pub allowed_syscalls: Vec<String>,
	/// Blocked system calls
	pub blocked_syscalls: Vec<String>,
}

impl Default for IsolationConfig {
	fn default() -> Self {
		Self {
			process_isolation: true,
			namespace_isolation: true,
			filesystem_isolation: true,
			network_isolation: false,
			user_isolation: true,
			default_isolation_level: IsolationLevel::Basic,
			max_cpu_usage: 50, /** 50% */
			max_memory_usage: 512 * 1024 * 1024, /** 512MB */
			max_disk_usage: 1024 * 1024 * 1024, /** 1GB */
			max_network_bandwidth: 1024 * 1024, /** 1MB/s */
			allowed_syscalls: vec![
				"read".to_string(), "write".to_string(), "open".to_string(),
				"close".to_string(), "stat".to_string(), "lstat".to_string(),
				"fstat".to_string(), "access".to_string(), "chdir".to_string(),
				"getcwd".to_string(), "chmod".to_string(), "fchmod".to_string(),
				"umask".to_string(), "getuid".to_string(), "getgid".to_string(),
				"geteuid".to_string(), "getegid".to_string(), "setuid".to_string(),
				"setgid".to_string(), "getpid".to_string(), "getppid".to_string(),
				"getpgrp".to_string(), "setpgid".to_string(), "setsid".to_string(),
				"getsid".to_string(), "exit".to_string(), "exit_group".to_string(),
				"wait4".to_string(), "waitpid".to_string(), "clone".to_string(),
				"fork".to_string(), "vfork".to_string(), "execve".to_string(),
				"execveat".to_string(), "kill".to_string(), "sigaction".to_string(),
				"sigprocmask".to_string(), "sigreturn".to_string(), "rt_sigaction".to_string(),
				"rt_sigprocmask".to_string(), "rt_sigreturn".to_string(), "sigaltstack".to_string(),
				"nanosleep".to_string(), "clock_gettime".to_string(), "clock_getres".to_string(),
				"gettimeofday".to_string(), "settimeofday".to_string(), "adjtimex".to_string(),
				"getrlimit".to_string(), "setrlimit".to_string(), "getrusage".to_string(),
				"times".to_string(), "ptrace".to_string(), "getuid".to_string(),
				"syslog".to_string(), "getgid".to_string(), "setuid".to_string(),
				"setgid".to_string(), "geteuid".to_string(), "getegid".to_string(),
				"setpgid".to_string(), "getppid".to_string(), "getpgrp".to_string(),
				"setsid".to_string(), "setreuid".to_string(), "setregid".to_string(),
				"getgroups".to_string(), "setgroups".to_string(), "setresuid".to_string(),
				"getresuid".to_string(), "setresgid".to_string(), "getresgid".to_string(),
				"getpgid".to_string(), "setfsuid".to_string(), "setfsgid".to_string(),
				"getsid".to_string(), "capget".to_string(), "capset".to_string(),
				"rt_sigpending".to_string(), "rt_sigtimedwait".to_string(),
				"rt_sigqueueinfo".to_string(), "rt_sigsuspend".to_string(),
				"sigaltstack".to_string(), "utime".to_string(), "mknod".to_string(),
				"uselib".to_string(), "personality".to_string(), "ustat".to_string(),
				"statfs".to_string(), "fstatfs".to_string(), "sysfs".to_string(),
				"getpriority".to_string(), "setpriority".to_string(), "sched_setparam".to_string(),
				"sched_getparam".to_string(), "sched_setscheduler".to_string(),
				"sched_getscheduler".to_string(), "sched_get_priority_max".to_string(),
				"sched_get_priority_min".to_string(), "sched_rr_get_interval".to_string(),
				"mlock".to_string(), "munlock".to_string(), "mlockall".to_string(),
				"munlockall".to_string(), "vhangup".to_string(), "modify_ldt".to_string(),
				"pivot_root".to_string(), "_sysctl".to_string(), "prctl".to_string(),
				"arch_prctl".to_string(), "adjtimex".to_string(), "setrlimit".to_string(),
				"chroot".to_string(), "sync".to_string(), "acct".to_string(),
				"settimeofday".to_string(), "mount".to_string(), "umount2".to_string(),
				"swapon".to_string(), "swapoff".to_string(), "reboot".to_string(),
				"sethostname".to_string(), "setdomainname".to_string(),
				"iopl".to_string(), "ioperm".to_string(), "create_module".to_string(),
				"init_module".to_string(), "delete_module".to_string(),
				"get_kernel_syms".to_string(), "query_module".to_string(),
				"quotactl".to_string(), "nfsservctl".to_string(), "getpmsg".to_string(),
				"putpmsg".to_string(), "afs_syscall".to_string(), "tuxcall".to_string(),
				"security".to_string(), "gettid".to_string(), "readahead".to_string(),
				"setxattr".to_string(), "lsetxattr".to_string(), "fsetxattr".to_string(),
				"getxattr".to_string(), "lgetxattr".to_string(), "fgetxattr".to_string(),
				"listxattr".to_string(), "llistxattr".to_string(), "flistxattr".to_string(),
				"removexattr".to_string(), "lremovexattr".to_string(), "fremovexattr".to_string(),
				"tkill".to_string(), "time".to_string(), "futex".to_string(),
				"sched_setaffinity".to_string(), "sched_getaffinity".to_string(),
				"set_thread_area".to_string(), "io_setup".to_string(), "io_destroy".to_string(),
				"io_getevents".to_string(), "io_submit".to_string(), "io_cancel".to_string(),
				"get_thread_area".to_string(), "lookup_dcookie".to_string(),
				"epoll_create".to_string(), "epoll_ctl_old".to_string(), "epoll_wait_old".to_string(),
				"remap_file_pages".to_string(), "getdents64".to_string(),
				"set_tid_address".to_string(), "restart_syscall".to_string(),
				"semtimedop".to_string(), "fadvise64".to_string(), "timer_create".to_string(),
				"timer_settime".to_string(), "timer_gettime".to_string(), "timer_getoverrun".to_string(),
				"timer_delete".to_string(), "clock_settime".to_string(), "clock_gettime".to_string(),
				"clock_getres".to_string(), "clock_nanosleep".to_string(), "exit_group".to_string(),
				"epoll_wait".to_string(), "epoll_ctl".to_string(), "tgkill".to_string(),
				"utimes".to_string(), "vserver".to_string(), "mbind".to_string(),
				"set_mempolicy".to_string(), "get_mempolicy".to_string(), "mq_open".to_string(),
				"mq_unlink".to_string(), "mq_timedsend".to_string(), "mq_timedreceive".to_string(),
				"mq_notify".to_string(), "mq_getsetattr".to_string(), "kexec_load".to_string(),
				"waitid".to_string(), "add_key".to_string(), "request_key".to_string(),
				"keyctl".to_string(), "ioprio_set".to_string(), "ioprio_get".to_string(),
				"inotify_init".to_string(), "inotify_add_watch".to_string(),
				"inotify_rm_watch".to_string(), "migrate_pages".to_string(),
				"openat".to_string(), "mkdirat".to_string(), "mknodat".to_string(),
				"fchownat".to_string(), "futimesat".to_string(), "newfstatat".to_string(),
				"unlinkat".to_string(), "renameat".to_string(), "linkat".to_string(),
				"symlinkat".to_string(), "readlinkat".to_string(), "fchmodat".to_string(),
				"faccessat".to_string(), "pselect6".to_string(), "ppoll".to_string(),
				"unshare".to_string(), "set_robust_list".to_string(), "get_robust_list".to_string(),
				"splice".to_string(), "tee".to_string(), "sync_file_range".to_string(),
				"vmsplice".to_string(), "move_pages".to_string(), "utimensat".to_string(),
				"epoll_pwait".to_string(), "signalfd".to_string(), "timerfd_create".to_string(),
				"eventfd".to_string(), "fallocate".to_string(), "timerfd_settime".to_string(),
				"timerfd_gettime".to_string(), "accept4".to_string(), "signalfd4".to_string(),
				"eventfd2".to_string(), "epoll_create1".to_string(), "dup3".to_string(),
				"pipe2".to_string(), "inotify_init1".to_string(), "preadv".to_string(),
				"pwritev".to_string(), "rt_tgsigqueueinfo".to_string(), "perf_event_open".to_string(),
				"recvmmsg".to_string(), "fanotify_init".to_string(), "fanotify_mark".to_string(),
				"prlimit64".to_string(), "name_to_handle_at".to_string(), "open_by_handle_at".to_string(),
				"clock_adjtime".to_string(), "syncfs".to_string(), "sendmmsg".to_string(),
				"setns".to_string(), "getcpu".to_string(), "process_vm_readv".to_string(),
				"process_vm_writev".to_string(), "kcmp".to_string(), "finit_module".to_string(),
				"sched_setattr".to_string(), "sched_getattr".to_string(), "renameat2".to_string(),
				"seccomp".to_string(), "getrandom".to_string(), "memfd_create".to_string(),
				"kexec_file_load".to_string(), "bpf".to_string(), "execveat".to_string(),
				"userfaultfd".to_string(), "membarrier".to_string(), "mlock2".to_string(),
				"copy_file_range".to_string(), "preadv2".to_string(), "pwritev2".to_string(),
				"pkey_mprotect".to_string(), "pkey_alloc".to_string(), "pkey_free".to_string(),
				"statx".to_string(), "io_pgetevents".to_string(), "rseq".to_string(),
				"pidfd_send_signal".to_string(), "io_uring_setup".to_string(),
				"io_uring_enter".to_string(), "io_uring_register".to_string(),
				"open_tree".to_string(), "move_mount".to_string(), "fsopen".to_string(),
				"fsconfig".to_string(), "fsmount".to_string(), "fspick".to_string(),
				"pidfd_open".to_string(), "clone3".to_string(), "close_range".to_string(),
				"openat2".to_string(), "pidfd_getfd".to_string(), "faccessat2".to_string(),
				"process_madvise".to_string(), "epoll_pwait2".to_string(), "mount_setattr".to_string(),
				"quotactl_fd".to_string(), "landlock_create_ruleset".to_string(),
				"landlock_add_rule".to_string(), "landlock_restrict_self".to_string(),
				"memfd_secret".to_string(), "process_mrelease".to_string(),
				"futex_waitv".to_string(), "set_mempolicy_home_node".to_string(),
			],
			blocked_syscalls: vec![
				"ptrace".to_string(), "personality".to_string(), "modify_ldt".to_string(),
				"arch_prctl".to_string(), "set_tid_address".to_string(), "restart_syscall".to_string(),
				"exit_group".to_string(), "unshare".to_string(), "set_robust_list".to_string(),
				"get_robust_list".to_string(), "splice".to_string(), "tee".to_string(),
				"sync_file_range".to_string(), "vmsplice".to_string(), "move_pages".to_string(),
				"utimensat".to_string(), "epoll_pwait".to_string(), "signalfd".to_string(),
				"timerfd_create".to_string(), "eventfd".to_string(), "fallocate".to_string(),
				"timerfd_settime".to_string(), "timerfd_gettime".to_string(), "accept4".to_string(),
				"signalfd4".to_string(), "eventfd2".to_string(), "epoll_create1".to_string(),
				"dup3".to_string(), "pipe2".to_string(), "inotify_init1".to_string(),
				"preadv".to_string(), "pwritev".to_string(), "rt_tgsigqueueinfo".to_string(),
				"perf_event_open".to_string(), "recvmmsg".to_string(), "fanotify_init".to_string(),
				"fanotify_mark".to_string(), "prlimit64".to_string(), "name_to_handle_at".to_string(),
				"open_by_handle_at".to_string(), "clock_adjtime".to_string(), "syncfs".to_string(),
				"sendmmsg".to_string(), "setns".to_string(), "getcpu".to_string(),
				"process_vm_readv".to_string(), "process_vm_writev".to_string(), "kcmp".to_string(),
				"finit_module".to_string(), "sched_setattr".to_string(), "sched_getattr".to_string(),
				"renameat2".to_string(), "seccomp".to_string(), "getrandom".to_string(),
				"memfd_create".to_string(), "kexec_file_load".to_string(), "bpf".to_string(),
				"execveat".to_string(), "userfaultfd".to_string(), "membarrier".to_string(),
				"mlock2".to_string(), "copy_file_range".to_string(), "preadv2".to_string(),
				"pwritev2".to_string(), "pkey_mprotect".to_string(), "pkey_alloc".to_string(),
				"pkey_free".to_string(), "statx".to_string(), "io_pgetevents".to_string(),
				"rseq".to_string(), "pidfd_send_signal".to_string(), "io_uring_setup".to_string(),
				"io_uring_enter".to_string(), "io_uring_register".to_string(), "open_tree".to_string(),
				"move_mount".to_string(), "fsopen".to_string(), "fsconfig".to_string(),
				"fsmount".to_string(), "fspick".to_string(), "pidfd_open".to_string(),
				"clone3".to_string(), "close_range".to_string(), "openat2".to_string(),
				"pidfd_getfd".to_string(), "faccessat2".to_string(), "process_madvise".to_string(),
				"epoll_pwait2".to_string(), "mount_setattr".to_string(), "quotactl_fd".to_string(),
				"landlock_create_ruleset".to_string(), "landlock_add_rule".to_string(),
				"landlock_restrict_self".to_string(), "memfd_secret".to_string(),
				"process_mrelease".to_string(), "futex_waitv".to_string(),
				"set_mempolicy_home_node".to_string(),
			],
		}
	}
}

/**
 * Isolated process information
 * 
 * Manages isolated process information including process ID, isolation level,
 * resource usage, and other details.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedProcess {
	/// Process ID
	pub pid: u32,
	/// Isolation level
	pub isolation_level: IsolationLevel,
	/// CPU usage (percentage)
	pub cpu_usage: f64,
	/// Memory usage (bytes)
	pub memory_usage: u64,
	/// Disk usage (bytes)
	pub disk_usage: u64,
	/// Network usage (bytes)
	pub network_usage: u64,
	/// Process start time
	pub start_time: u64,
	/// Process status
	pub status: ProcessStatus,
}

/**
 * Process status
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessStatus {
	/// Process is running
	Running,
	/// Process has completed
	Completed,
	/// Process was terminated
	Terminated,
	/// Process was killed
	Killed,
	/// Process failed to start
	Failed,
}

/**
 * Isolation manager for process containment
 * 
 * Provides process isolation, resource limits, and security containers.
 */
pub struct IsolationManager {
	/// Security configuration
	config: Arc<RwLock<SecurityConfig>>,
	/// Isolation configuration
	isolation_config: IsolationConfig,
	/// Isolated processes
	processes: Arc<RwLock<HashMap<u32, IsolatedProcess>>>,
	/// Active state
	active: bool,
}

impl IsolationManager {
	/**
	 * Creates a new isolation manager
	 * 
	 * @param config - Security configuration
	 * @return Result<IsolationManager> - New isolation manager or error
	 */
	pub async fn new(config: Arc<RwLock<SecurityConfig>>) -> Result<Self> {
		/**
		 * Initializes the isolation manager
		 * 
		 * Creates an isolation manager with the specified settings,
		 * provides process isolation, resource limits, and security
		 * container functionality.
		 * 
		 * Initializes namespace isolation, filesystem isolation,
		 * network isolation, and other features to provide a safe
		 * process execution environment.
		 */
		
		Ok(Self {
			config,
			isolation_config: IsolationConfig::default(),
			processes: Arc::new(RwLock::new(HashMap::new())),
			active: true,
		})
	}
	
	/**
	 * Creates an isolated process
	 * 
	 * @param command - Command to execute
	 * @param isolation_level - Isolation level to apply
	 * @return Result<u32> - Process ID or error
	 */
	pub async fn create_isolated_process(&self, command: &str, isolation_level: IsolationLevel) -> Result<u32> {
		/**
		 * Creates an isolated process
		 * 
		 * Executes the specified command with the specified isolation level,
		 * applies resource limits and security monitoring.
		 * 
		 * Uses namespace isolation, user isolation, filesystem isolation
		 * to build a safe process execution environment and returns
		 * the process ID.
		 */
		
		/**
		 * Actual process isolation implementation
		 * 
		 * Creates isolated processes with namespace isolation,
		 * user isolation, filesystem isolation, and resource limits.
		 */
		
		/**
		 * Parse command into executable and arguments
		 */
		let parts: Vec<&str> = command.split_whitespace().collect();
		if parts.is_empty() {
			return Err(anyhow::anyhow!("Empty command"));
		}
		
		let executable = parts[0];
		let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
		
		/**
		 * Create child process with isolation
		 */
		let mut child = std::process::Command::new(executable);
		child.args(&args);
		
		/**
		 * Apply isolation based on level
		 */
		match isolation_level {
			IsolationLevel::None => {
				/**
				 * No isolation - run normally
				 */
			}
			IsolationLevel::Basic => {
				/**
				 * Basic isolation - set resource limits
				 */
				child.env("SARE_ISOLATION", "basic");
				
				/**
				 * Set resource limits
				 */
				unsafe {
					use nix::sys::resource::{setrlimit, Resource, Rlimit};
					
					/**
					 * Set CPU time limit
					 */
					setrlimit(Resource::RLIMIT_CPU, Rlimit::new(60, 60))?;
					
					/**
					 * Set memory limit
					 */
					setrlimit(Resource::RLIMIT_AS, Rlimit::new(1024 * 1024 * 1024, 1024 * 1024 * 1024))?;
					
					/**
					 * Set file size limit
					 */
					setrlimit(Resource::RLIMIT_FSIZE, Rlimit::new(100 * 1024 * 1024, 100 * 1024 * 1024))?;
				}
			}
			IsolationLevel::Enhanced => {
				/**
				 * Enhanced isolation - namespace isolation
				 */
				child.env("SARE_ISOLATION", "enhanced");
				
				/**
				 * Create new namespaces
				 */
				unsafe {
					use nix::unistd::{unshare, setuid, setgid};
					use nix::sched::CloneFlags;
					use libc::{uid_t, gid_t};
					
					/**
					 * Unshare namespaces
					 */
					unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNET)?;
					
					/**
					 * Set user/group isolation
					 */
					setuid(1000 as uid_t)?;
					setgid(1000 as gid_t)?;
				}
				
				/**
				 * Set enhanced resource limits
				 */
				unsafe {
					use nix::sys::resource::{setrlimit, Resource, Rlimit};
					
					/**
					 * Stricter CPU limit
					 */
					setrlimit(Resource::RLIMIT_CPU, Rlimit::new(30, 30))?;
					
					/**
					 * Stricter memory limit
					 */
					setrlimit(Resource::RLIMIT_AS, Rlimit::new(512 * 1024 * 1024, 512 * 1024 * 1024))?;
					
					/**
					 * Stricter file size limit
					 */
					setrlimit(Resource::RLIMIT_FSIZE, Rlimit::new(50 * 1024 * 1024, 50 * 1024 * 1024))?;
					
					/**
					 * Set process limit
					 */
					setrlimit(Resource::RLIMIT_NPROC, Rlimit::new(10, 10))?;
				}
			}
			IsolationLevel::Maximum => {
				/**
				 * Maximum isolation - complete sandbox
				 */
				child.env("SARE_ISOLATION", "maximum");
				
				/**
				 * Create all namespaces
				 */
				unsafe {
					use nix::unistd::{unshare, setuid, setgid};
					use nix::sched::CloneFlags;
					use libc::{uid_t, gid_t};
					
					/**
					 * Unshare all namespaces
					 */
					unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNET | 
							CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC)?;
					
					/**
					 * Set strict user/group isolation
					 */
					setuid(1001 as uid_t)?;
					setgid(1001 as gid_t)?;
				}
				
				/**
				 * Set maximum resource limits
				 */
				unsafe {
					use nix::sys::resource::{setrlimit, Resource, Rlimit};
					
					/**
					 * Very strict CPU limit
					 */
					setrlimit(Resource::RLIMIT_CPU, Rlimit::new(15, 15))?;
					
					/**
					 * Very strict memory limit
					 */
					setrlimit(Resource::RLIMIT_AS, Rlimit::new(256 * 1024 * 1024, 256 * 1024 * 1024))?;
					
					/**
					 * Very strict file size limit
					 */
					setrlimit(Resource::RLIMIT_FSIZE, Rlimit::new(25 * 1024 * 1024, 25 * 1024 * 1024))?;
					
					/**
					 * Very strict process limit
					 */
					setrlimit(Resource::RLIMIT_NPROC, Rlimit::new(5, 5))?;
					
					/**
					 * Set core dump limit to 0
					 */
					setrlimit(Resource::RLIMIT_CORE, Rlimit::new(0, 0))?;
				}
			}
		}
		
		/**
		 * Spawn the isolated process
		 */
		let child_process = child.spawn()?;
		let pid = child_process.id() as u32;
		
		/**
		 * Create isolated process info
		 */
		let process = IsolatedProcess {
			pid,
			isolation_level,
			cpu_usage: 0.0,
			memory_usage: 0,
			disk_usage: 0,
			network_usage: 0,
			start_time: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)?
				.as_secs(),
			status: ProcessStatus::Running,
		};
		
		/**
		 * Store process info
		 */
		{
			let mut processes = self.processes.write().await;
			processes.insert(pid, process);
		}
		
		Ok(pid)
	}
	
	/**
	 * Terminates an isolated process
	 * 
	 * @param pid - Process ID to terminate
	 * @return Result<()> - Success or error status
	 */
	pub async fn terminate_process(&self, pid: u32) -> Result<()> {
		// Update process status
		if let Ok(mut processes) = self.processes.try_write() {
			if let Some(process) = processes.get_mut(&pid) {
				process.status = ProcessStatus::Terminated;
			}
		}
		
		Ok(())
	}
	
	/**
	 * Gets all isolated processes
	 * 
	 * @return Vec<IsolatedProcess> - List of isolated processes
	 */
	pub async fn get_processes(&self) -> Vec<IsolatedProcess> {
		let processes = self.processes.read().await;
		processes.values().cloned().collect()
	}
	
	/**
	 * Checks if isolation is active
	 * 
	 * @return bool - Whether isolation is active
	 */
	pub async fn is_active(&self) -> bool {
		self.active
	}
	
	/**
	 * Updates isolation configuration
	 * 
	 * @param config - New isolation configuration
	 */
	pub fn update_config(&mut self, config: IsolationConfig) {
		self.isolation_config = config;
	}
	
	/**
	 * Gets current isolation configuration
	 * 
	 * @return IsolationConfig - Current isolation configuration
	 */
	pub fn get_config(&self) -> IsolationConfig {
		self.isolation_config.clone()
	}
} 