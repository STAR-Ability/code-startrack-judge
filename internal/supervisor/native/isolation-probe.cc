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
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
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
static std::string readonlyFailure;
static int readonlyMountCount=0,readonlyWriteDeniedCount=0,readonlyEROFSCount=0,readonlyEACCESCount=0,readonlyEPERMCount=0;
static bool readonly() {
    for (auto name : {"/usr/.startrack-isolation-probe","/bin/.startrack-isolation-probe","/lib/.startrack-isolation-probe","/lib64/.startrack-isolation-probe","/etc/alternatives/.startrack-isolation-probe","/etc/texmf/.startrack-isolation-probe","/etc/fonts/.startrack-isolation-probe","/var/lib/texmf/.startrack-isolation-probe","/etc/ld.so.cache"}) {
        std::string path=name;auto slash=path.rfind('/');const auto mounted=std::strstr(name,".startrack")?path.substr(0,slash):path;
        struct statvfs fs{};if(statvfs(mounted.c_str(),&fs)!=0||(fs.f_flag&ST_RDONLY)==0){readonlyFailure=mounted+":mountWritable";return false;}
        ++readonlyMountCount;
        int fd=open(name,O_WRONLY|O_CREAT|O_CLOEXEC,0600);
        if(fd>=0){close(fd);if(std::strstr(name,".startrack"))unlink(name);readonlyFailure=std::string(name)+":writable";return false;}
        // DAC or the inherited AppArmor rule may deny an existing-file write
        // before VFS reports EROFS. Positive ST_RDONLY remains mandatory.
        if(errno!=EROFS&&errno!=EACCES&&errno!=EPERM){readonlyFailure=std::string(name)+":"+std::to_string(errno);return false;}
        ++readonlyWriteDeniedCount;if(errno==EROFS)++readonlyEROFSCount;else if(errno==EACCES)++readonlyEACCESCount;else ++readonlyEPERMCount;
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
static bool privilegeAttemptDenied(int attempt){
    // Linux capability ABI v3 reads exactly two 12-byte data words.
    struct CapHeader{unsigned int version;int pid;} header{0x20080522,0};
    struct CapData{unsigned int effective,permitted,inheritable;} data[2]{{1u<<21,1u<<21,0},{0,0,0}};
    errno=0;long result=-2;
    switch(attempt){
    case 0:result=syscall(SYS_capset,&header,data);break;
    case 1:result=prctl(PR_SET_SECUREBITS,0,0,0,0);break;
    case 2:result=prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,21,0,0);break;
    case 3:result=syscall(SYS_setuid,0);break;
    case 4:result=syscall(SYS_unshare,CLONE_NEWUSER);break;
    case 5:result=syscall(SYS_unshare,CLONE_NEWNET);break;
    case 6:case 7:
        result=syscall(SYS_clone,(CLONE_NEWUSER|(attempt==7?CLONE_NEWNS:0))|SIGCHLD,nullptr,nullptr,nullptr,0);
        if(result==0)_exit(101);if(result>0){while(waitpid(result,nullptr,0)<0&&errno==EINTR){}return false;}break;
    case 8:case 9:{
        unsigned long long cloneArgs[11]{};cloneArgs[0]=CLONE_NEWUSER|(attempt==9?CLONE_NEWNS:0);cloneArgs[4]=SIGCHLD;
        result=syscall(SYS_clone3,cloneArgs,sizeof(cloneArgs));
        if(result==0)_exit(102);if(result>0){while(waitpid(result,nullptr,0)<0&&errno==EINTR){}return false;}break;}
    case 10:result=syscall(SYS_mount,"tmpfs","/w","tmpfs",0,"size=4k");break;
    case 11:result=syscall(SYS_pivot_root,"/__startrack_absent","/__startrack_absent/old");break;
    default:return false;
    }
    return result==-1&&(errno==EPERM||((attempt==8||attempt==9)&&errno==ENOSYS));
}
static std::string privilegeDenialFailure(){
    const char*names[]={"capset","securebits","ambient","setuid","unshareUser","unshareNetwork","cloneUser","cloneMount","clone3User","clone3Mount","mount","pivot"};
    // An unexpected successful syscall can change this child's credentials or
    // namespaces. Preserve the observed parent identity and report that escape.
    for(int attempt=0;attempt<12;++attempt){
        pid_t child=fork();if(child<0)return "probeFork";
        if(child==0)_exit(privilegeAttemptDenied(attempt)?0:103);
        int status=0;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
        if(waited!=child||!WIFEXITED(status)||WEXITSTATUS(status)!=0)return names[attempt];
    }
    return "";
}
int main(int argc,char**argv){
    if(argc!=3)return 2;std::string mode=argv[1],nonce=argv[2];
    if(nonce.size()!=32||nonce.find_first_not_of("0123456789abcdef")!=std::string::npos)return 2;
    if(mode=="cpu"){volatile unsigned long n=0;for(;;)++n;}
    if(mode=="wall"){sleep(30);return 3;}
    if(mode=="memory"){
        // Strict upstream memory mode also applies RLIMIT_DATA; malloc may
        // return ENOMEM before the cgroup fills. Committing this private tmpfs
        // mapping measures the same hard cgroup limit without changing it.
        usleep(100000); // Positively witness this owned group before pressure.
        const size_t size=64<<20;int fd=open("/w/.memory-pressure",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if(fd<0||ftruncate(fd,size)!=0)return 4;
        volatile char*p=(volatile char*)mmap(nullptr,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);close(fd);
        if(p==MAP_FAILED)return 4;for(size_t i=0;i<size;i+=4096)p[i]=1;return 4;
    }
    if(mode=="output"){usleep(100000);char b[4096]{};for(;;)if(write(1,b,sizeof(b))<0)return 5;}
    if(mode=="fork"){
        int count=0;for(int i=0;i<64;++i){pid_t p=fork();if(p<0)break;if(p==0){for(;;)pause();}++count;}
        usleep(100000); // Witness all live descendants before the parent returns.
        std::cout<<count<<"\n";return count>0&&count<8?0:6;
    }
    if(mode=="dirty"){int fd=open("/w/.previous-execution",O_WRONLY|O_CREAT,0600);if(fd<0)return 7;write(fd,"synthetic",9);close(fd);usleep(100000);return 0;}
    if(mode!="inspect"&&mode!="inspect-a"&&mode!="inspect-b")return 8;
    if(mode!="inspect"){const char*own=mode=="inspect-a"?"/w/.peer-a":"/w/.peer-b";int fd=open(own,O_WRONLY|O_CREAT|O_CLOEXEC,0644);if(fd<0)return 9;if(write(fd,"synthetic",9)!=9)return 10;close(fd);struct stat st{};if(stat(own,&st)!=0||(st.st_mode&0777)!=0644||read(own)!="synthetic")return 11;}
    const auto status=read("/proc/self/status"), maps=read("/proc/self/uid_map"), mounts=read("/proc/self/mountinfo");
    bool privateMounts=mounts.find(" shared:")==std::string::npos&&mounts.find(" master:")==std::string::npos;
    bool creds=true;extern char**environ;for(char**p=environ;*p;++p){std::string e=*p;if(e.find("TOKEN=")!=std::string::npos||e.find("PASSWORD=")!=std::string::npos||e.find("SECRET=")!=std::string::npos||e.find("DATABASE=")!=std::string::npos||e.rfind("ES_",0)==0||e.rfind("AWS_",0)==0)creds=false;}
    bool files=denied("/run/secrets/startrack/database-url")&&denied("/var/lib/startrack/private")&&denied("/var/run/docker.sock")&&denied("/proc/1/root/run/secrets/startrack/database-url")&&denied("/w/.previous-execution");
    for(auto helper:{"/opt/startrack/libexec/default_validator","/opt/startrack/libexec/default_grader","/opt/startrack/libexec/problemtools-bridge.py","/w/default_validator","/w/default_grader","/w/problemtools-bridge.py"})files=files&&absent(helper);
    int securebits=prctl(PR_GET_SECUREBITS);
    const auto denialFailure=privilegeDenialFailure();
    unsigned long nsUID=0,hostUID=0,length=0,executionUID=0;std::istringstream uidMap(maps);
    while(uidMap>>nsUID>>hostUID>>length)if(nsUID==1000&&length==1)executionUID=hostUID;
    usleep(200000); // Keep simultaneous environments alive for the cgroup sampler.
    bool peerFilesystem=mode=="inspect"||(mode=="inspect-a"?absent("/w/.peer-b"):absent("/w/.peer-a"));
    std::cout<<std::boolalpha<<"{\"uid\":"<<getuid()<<",\"gid\":"<<getgid()<<",\"executionUID\":"<<executionUID
      <<",\"seccomp\":"<<(std::stoi(field(status,"Seccomp"))==2&&std::stoi(field(status,"Seccomp_filters"))>=3&&denialFailure.empty())
      <<",\"seccompFilters\":"<<std::stoi(field(status,"Seccomp_filters"))
      <<",\"capsZero\":"<<(std::stoul(field(status,"CapEff"),nullptr,16)==0&&std::stoul(field(status,"CapPrm"),nullptr,16)==0&&std::stoul(field(status,"CapInh"),nullptr,16)==0&&std::stoul(field(status,"CapAmb"),nullptr,16)==0&&securebits==47)
      <<",\"capabilityEffectiveBits\":"<<std::stoul(field(status,"CapEff"),nullptr,16)
      <<",\"capabilityPermittedBits\":"<<std::stoul(field(status,"CapPrm"),nullptr,16)
      <<",\"capabilityInheritableBits\":"<<std::stoul(field(status,"CapInh"),nullptr,16)
      <<",\"capabilityAmbientBits\":"<<std::stoul(field(status,"CapAmb"),nullptr,16)
      <<",\"capabilityBoundingBits\":"<<std::stoul(field(status,"CapBnd"),nullptr,16)
      <<",\"securebits\":"<<securebits<<",\"denialFailure\":\""<<denialFailure<<"\""
      <<",\"noNewPrivileges\":"<<(std::stoi(field(status,"NoNewPrivs"))==1)
      <<",\"privateMounts\":"<<privateMounts<<",\"readonly\":"<<readonly()
      <<",\"readonlyFailure\":\""<<readonlyFailure<<"\""
      <<",\"readonlyMountCount\":"<<readonlyMountCount<<",\"readonlyWriteDeniedCount\":"<<readonlyWriteDeniedCount
      <<",\"readonlyEROFSCount\":"<<readonlyEROFSCount<<",\"readonlyEACCESCount\":"<<readonlyEACCESCount<<",\"readonlyEPERMCount\":"<<readonlyEPERMCount
      <<",\"filesystem\":"<<files<<",\"credentials\":"<<creds
      <<",\"peerFilesystem\":"<<peerFilesystem
      <<",\"siblingProc\":"<<(denied("/proc/1/environ")&&denied("/proc/1/mem")&&denied("/proc/1/fd/3"))
      <<",\"descriptors\":"<<privateDescriptors()<<",\"pidNamespace\":\""<<namespaceID("/proc/self/ns/pid")
      <<"\",\"netNamespace\":\""<<namespaceID("/proc/self/ns/net")<<"\",\"network\":"<<networkDenied()<<"}\n";
    return 0;
}
