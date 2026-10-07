// Fixed synthetic qualification fixture. Compile and execute only in go-judge.
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static std::string read(const char *name) {
    std::ifstream in(name); std::ostringstream out; out << in.rdbuf(); return out.str();
}
static std::string field(const std::string &text, const std::string &key) {
    std::istringstream in(text); std::string line;
    while (std::getline(in,line)) if (line.rfind(key+":",0)==0) return line.substr(key.size()+1);
    return "";
}
static bool denied(const char *name) {
    int fd=open(name,O_RDONLY|O_CLOEXEC); if(fd>=0){close(fd);return false;} return true;
}
static bool absent(const char*name){struct stat st{};return lstat(name,&st)<0&&errno==ENOENT;}
static bool readonly() {
    for (auto name : {"/usr/.startrack-isolation-probe","/bin/.startrack-isolation-probe","/lib/.startrack-isolation-probe","/lib64/.startrack-isolation-probe","/etc/alternatives/.startrack-isolation-probe","/etc/texmf/.startrack-isolation-probe","/etc/fonts/.startrack-isolation-probe","/var/lib/texmf/.startrack-isolation-probe","/etc/ld.so.cache"}) {
        int fd=open(name,O_WRONLY|O_CREAT|O_CLOEXEC,0600);
        if(fd>=0){close(fd);if(std::strstr(name,".startrack"))unlink(name);return false;}
        if(errno!=EROFS) return false;
    }
    return true;
}
static bool networkDenied() {
    // An empty, down network namespace is positive enforcement evidence.
    // Connectivity failure by itself could merely mean that a peer is absent.
    ifaddrs *interfaces=nullptr;if(getifaddrs(&interfaces)!=0)return false;
    bool isolated=true;for(ifaddrs *p=interfaces;p;p=p->ifa_next){if(std::strcmp(p->ifa_name,"lo")!=0||(p->ifa_flags&IFF_UP))isolated=false;}
    freeifaddrs(interfaces);if(!isolated)return false;
    std::istringstream routes(read("/proc/net/route"));std::string line;std::getline(routes,line);while(std::getline(routes,line))if(line.find_first_not_of(" \t\r\n")!=std::string::npos)return false;
    if(!read("/proc/net/if_inet6").empty())return false;
    for (auto item : {std::pair<const char*,int>{"127.0.0.1",5050},{"127.0.0.1",8082},{"127.0.0.11",53},{"172.17.0.1",8082},{"169.254.169.254",80},{"1.1.1.1",443}}) {
        int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if(fd<0) continue;
        sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(item.second);inet_pton(AF_INET,item.first,&addr.sin_addr);
        int result=connect(fd,(sockaddr*)&addr,sizeof(addr));
        if(result==0){close(fd);return false;}
        if(errno==EINPROGRESS){pollfd p{fd,POLLOUT,0};poll(&p,1,100);int error=0;socklen_t size=sizeof(error);getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size);if(error==0){close(fd);return false;}}
        close(fd);
    }
    return true;
}
static std::string namespaceID(const char*name){char data[64]{};ssize_t n=readlink(name,data,sizeof(data)-1);return n>0?std::string(data,n):"";}
static bool privateDescriptors(){DIR*d=opendir("/proc/self/fd");if(!d)return false;int iterator=dirfd(d);bool safe=true;while(auto*e=readdir(d)){char*end=nullptr;long fd=strtol(e->d_name,&end,10);if(end&&*end==0&&fd>=3&&fd!=iterator)safe=false;}closedir(d);return safe;}
static bool privilegeRegainDenied(){
    // Linux capability ABI v3 reads exactly two 12-byte data words.
    struct CapHeader{unsigned int version;int pid;} header{0x20080522,0};
    struct CapData{unsigned int effective,permitted,inheritable;} data[2]{{1u<<21,1u<<21,0},{0,0,0}};
    errno=0;if(syscall(SYS_capset,&header,data)!=-1||errno!=EPERM)return false;
    errno=0;if(prctl(PR_SET_SECUREBITS,0,0,0,0)!=-1||errno!=EPERM)return false;
    errno=0;if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,21,0,0)!=-1||errno!=EPERM)return false;
    errno=0;if(syscall(SYS_setuid,0)!=-1||errno!=EPERM||getuid()!=1000||geteuid()!=1000)return false;
    errno=0;if(syscall(SYS_unshare,CLONE_NEWUSER)!=-1||errno!=EPERM)return false;
    for(auto flags:{CLONE_NEWUSER,CLONE_NEWUSER|CLONE_NEWNS}){
        errno=0;long cloned=syscall(SYS_clone,flags|SIGCHLD,nullptr,nullptr,nullptr,0);
        if(cloned==0)_exit(101);if(cloned>0){waitpid(cloned,nullptr,0);return false;}if(errno!=EPERM)return false;
        unsigned long long cloneArgs[11]{};cloneArgs[0]=flags;cloneArgs[4]=SIGCHLD;
        errno=0;cloned=syscall(SYS_clone3,cloneArgs,sizeof(cloneArgs));
        if(cloned==0)_exit(102);if(cloned>0){waitpid(cloned,nullptr,0);return false;}if(errno!=EPERM&&errno!=ENOSYS)return false;
    }
    errno=0;if(syscall(SYS_mount,"tmpfs","/w","tmpfs",0,"size=4k")!=-1||errno!=EPERM)return false;
    return true;
}
int main(int argc,char**argv){
    if(argc!=2)return 2;std::string mode=argv[1];
    if(mode=="cpu"){volatile unsigned long n=0;for(;;)++n;}
    if(mode=="wall"){sleep(30);return 3;}
    if(mode=="memory"){for(;;){volatile char*p=(char*)malloc(8<<20);if(!p)return 4;for(int i=0;i<(8<<20);i+=4096)p[i]=1;}}
    if(mode=="output"){char b[4096]{};for(;;)if(write(1,b,sizeof(b))<0)return 5;}
    if(mode=="fork"){
        int count=0;for(int i=0;i<64;++i){pid_t p=fork();if(p<0)break;if(p==0){for(;;)pause();}++count;}
        std::cout<<count<<"\n";return count>0&&count<8?0:6;
    }
    if(mode=="dirty"){int fd=open("/w/.previous-execution",O_WRONLY|O_CREAT,0600);if(fd<0)return 7;write(fd,"synthetic",9);close(fd);return 0;}
    if(mode!="inspect"&&mode!="inspect-a"&&mode!="inspect-b")return 8;
    if(mode!="inspect"){const char*own=mode=="inspect-a"?"/w/.peer-a":"/w/.peer-b";int fd=open(own,O_WRONLY|O_CREAT|O_CLOEXEC,0644);if(fd<0)return 9;if(write(fd,"synthetic",9)!=9)return 10;close(fd);struct stat st{};if(stat(own,&st)!=0||(st.st_mode&0777)!=0644||read(own)!="synthetic")return 11;}
    const auto status=read("/proc/self/status"), maps=read("/proc/self/uid_map"), mounts=read("/proc/self/mountinfo");
    bool privateMounts=mounts.find(" shared:")==std::string::npos&&mounts.find(" master:")==std::string::npos;
    bool creds=true;extern char**environ;for(char**p=environ;*p;++p){std::string e=*p;if(e.find("TOKEN=")!=std::string::npos||e.find("PASSWORD=")!=std::string::npos||e.find("SECRET=")!=std::string::npos||e.find("DATABASE=")!=std::string::npos||e.rfind("ES_",0)==0||e.rfind("AWS_",0)==0)creds=false;}
    bool files=denied("/run/secrets/startrack/database-url")&&denied("/var/lib/startrack/private")&&denied("/var/run/docker.sock")&&denied("/proc/1/root/run/secrets/startrack/database-url")&&denied("/w/.previous-execution");
    for(auto helper:{"/opt/startrack/libexec/default_validator","/opt/startrack/libexec/default_grader","/opt/startrack/libexec/problemtools-bridge.py","/w/default_validator","/w/default_grader","/w/problemtools-bridge.py"})files=files&&absent(helper);
    errno=0;int privileged=syscall(SYS_unshare,CLONE_NEWNET);bool privilegedDenied=privileged<0&&errno==EPERM;
    errno=0;int pivot=syscall(SYS_pivot_root,"/__startrack_absent","/__startrack_absent/old");privilegedDenied=privilegedDenied&&pivot<0&&errno==EPERM;
    privilegedDenied=privilegedDenied&&privilegeRegainDenied();
    unsigned long nsUID=0,hostUID=0,length=0,executionUID=0;std::istringstream uidMap(maps);
    while(uidMap>>nsUID>>hostUID>>length)if(nsUID==1000&&length==1)executionUID=hostUID;
    usleep(200000); // Keep simultaneous environments alive for the cgroup sampler.
    bool peerFilesystem=mode=="inspect"||(mode=="inspect-a"?absent("/w/.peer-b"):absent("/w/.peer-a"));
    std::cout<<std::boolalpha<<"{\"uid\":"<<getuid()<<",\"gid\":"<<getgid()<<",\"executionUID\":"<<executionUID
      <<",\"seccomp\":"<<(std::stoi(field(status,"Seccomp"))==2&&std::stoi(field(status,"Seccomp_filters"))>=2&&privilegedDenied)
      <<",\"capsZero\":"<<(std::stoul(field(status,"CapEff"),nullptr,16)==0&&std::stoul(field(status,"CapPrm"),nullptr,16)==0&&std::stoul(field(status,"CapInh"),nullptr,16)==0&&std::stoul(field(status,"CapAmb"),nullptr,16)==0&&prctl(PR_GET_SECUREBITS)==47)
      <<",\"capabilityBoundingBits\":"<<std::stoul(field(status,"CapBnd"),nullptr,16)
      <<",\"noNewPrivileges\":"<<(std::stoi(field(status,"NoNewPrivs"))==1)
      <<",\"privateMounts\":"<<privateMounts<<",\"readonly\":"<<readonly()
      <<",\"filesystem\":"<<files<<",\"credentials\":"<<creds
      <<",\"peerFilesystem\":"<<peerFilesystem
      <<",\"siblingProc\":"<<(denied("/proc/1/environ")&&denied("/proc/1/mem")&&denied("/proc/1/fd/3"))
      <<",\"descriptors\":"<<privateDescriptors()<<",\"pidNamespace\":\""<<namespaceID("/proc/self/ns/pid")
      <<"\",\"netNamespace\":\""<<namespaceID("/proc/self/ns/net")<<"\",\"network\":"<<networkDenied()<<"}\n";
    return 0;
}
