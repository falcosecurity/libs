#include "libsinsp/cri-v1alpha2.grpc.pb.h"

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <fcntl.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <unistd.h>

#include <memory>
#include <set>

using namespace runtime::v1alpha2;

class FakeCRIServer final : public runtime::v1alpha2::RuntimeService::Service
{
public:
	FakeCRIServer(int delay_us,
	              ContainerStatusResponse&& cs,
	              PodSandboxStatusResponse&& ps,
	              ListContainersResponse&& lc,
	              const std::string& runtime_name)
	    : m_delay_us(delay_us),
	      m_container_status_response(cs),
	      m_pod_sandbox_status_response(ps),
	      m_list_containers_response(lc),
	      m_runtime_name(runtime_name)
	{
	}

	grpc::Status ContainerStatus(grpc::ServerContext* context,
	                             const ContainerStatusRequest* req,
	                             ContainerStatusResponse* resp)
	{
		usleep(m_delay_us);
		if (CONTAINER_IDS.find(req->container_id()) == CONTAINER_IDS.end())
		{
			std::cout << "CONTAINER NOT FOUND\n";
			return grpc::Status(
			    grpc::StatusCode::NOT_FOUND,
			    "fake_cri does not serve this container id: " + req->container_id());
		}
		resp->CopyFrom(m_container_status_response);
		resp->mutable_status()->set_id(req->container_id());
		return grpc::Status::OK;
	}

	grpc::Status ListContainers(grpc::ServerContext* context,
	                            const ListContainersRequest* req,
	                            ListContainersResponse* resp)
	{
		usleep(m_delay_us);
		resp->CopyFrom(m_list_containers_response);
		return grpc::Status::OK;
	}

	grpc::Status StopContainer(grpc::ServerContext* context,
	                           const StopContainerRequest* req,
	                           StopContainerResponse* resp)
	{
		usleep(m_delay_us);
		return grpc::Status::OK;
	}

	grpc::Status PodSandboxStatus(grpc::ServerContext* context,
	                              const PodSandboxStatusRequest* req,
	                              PodSandboxStatusResponse* resp)
	{
		usleep(m_delay_us);
		if (POD_SANDBOX_IDS.find(req->pod_sandbox_id()) == POD_SANDBOX_IDS.end())
		{
			return grpc::Status(
			    grpc::StatusCode::NOT_FOUND,
			    "fake_cri does not serve this pod sandbox id: " + req->pod_sandbox_id());
		}
		resp->CopyFrom(m_pod_sandbox_status_response);
		resp->mutable_status()->set_id(req->pod_sandbox_id());
		return grpc::Status::OK;
	}

	grpc::Status Version(grpc::ServerContext* context,
	                     const VersionRequest* req,
	                     VersionResponse* resp)
	{
		resp->set_version("0.1.0");
		resp->set_runtime_name(m_runtime_name);
		resp->set_runtime_version("1.1.2");
		resp->set_runtime_api_version("v1alpha2");
		return grpc::Status::OK;
	}

private:
	int m_delay_us;
	ContainerStatusResponse m_container_status_response;
	PodSandboxStatusResponse m_pod_sandbox_status_response;
	ListContainersResponse m_list_containers_response;
	std::string m_runtime_name;
	static const std::set<std::string> CONTAINER_IDS;
	static const std::set<std::string> POD_SANDBOX_IDS;
};

// The fake cri server will only answer to these container IDs/Pod sandbox ids
const std::set<std::string> FakeCRIServer::CONTAINER_IDS{
    "aec4c703604b4504df03108eef12e8256870eca8aabcb251855a35bf4f0337f1",
    "aec4c703604b",
    "ea457cc8202bb5684ddd4a2845ad7450ad48fb01448da5172790dcc4641757b9",
    "ea457cc8202b"};

const std::set<std::string> FakeCRIServer::POD_SANDBOX_IDS{
    "e16577158fb2003bc4d0a152dd0e2bda888235d0f131ff93390d16138c11c556",
    "e16577158fb2"};

class FakeCRIImageServer final : public runtime::v1alpha2::ImageService::Service
{
public:
	FakeCRIImageServer(ListImagesResponse&& is) : m_list_images_response(is) {}

	grpc::Status ListImages(grpc::ServerContext* context,
	                        const ListImagesRequest* req,
	                        ListImagesResponse* resp)
	{
		resp->CopyFrom(m_list_images_response);
		return grpc::Status::OK;
	}

private:
	ListImagesResponse m_list_images_response;
};

int main(int argc, char** argv)
{
	google::protobuf::io::FileOutputStream pb_stdout(1);
	int delay_us = 0;

	if (argc < 3)
	{
		fprintf(stderr,
		        "Usage: fake_cri [--nodelay|--slow|--veryslow] listen_addr pb_file_prefix "
		        "[runtime_name]\n");
		return 1;
	}

	if (argv[1] == std::string("--nodelay"))
	{
		// no delay, the default
		delay_us = 0;
		argv++;
	}
	else if (argv[1] == std::string("--slow"))
	{
		// 500 ms is slow but not slow enough to trigger the timeout
		delay_us = 500000;
		argv++;
	}
	else if (argv[1] == std::string("--veryslow"))
	{
		// 1200 ms is beyond the default 1 sec timeout so queries will fail
		delay_us = 1200000;
		argv++;
	}

	const char* addr = argv[1];
	const std::string pb_prefix(argv[2]);
	const std::string runtime(argc > 3 ? argv[3] : "containerd");

	ContainerStatusResponse cs;
	{
		const std::string path = pb_prefix + "_container.pb";
		int fd = open(path.c_str(), O_RDONLY);
		if(fd >= 0)
		{
			google::protobuf::io::FileInputStream fs(fd);
			google::protobuf::TextFormat::Parse(&fs, &cs);
			close(fd);
		}
		else
		{
			std::cout << "could not open file " << path << std::endl;
		}
	}

	PodSandboxStatusResponse ps;
	{
		const std::string path = pb_prefix + "_pod.pb";
		int fd = open(path.c_str(), O_RDONLY);
		if(fd >= 0)
		{
			google::protobuf::io::FileInputStream fs(fd);
			google::protobuf::TextFormat::Parse(&fs, &ps);
			close(fd);
		}
		else
		{
			std::cout << "could not open file " << path << std::endl;
		}
	}

	ListImagesResponse is;
	{
		const std::string path = pb_prefix + "_images.pb";
		int fd = open(path.c_str(), O_RDONLY);
		if (fd >= 0)
		{
			google::protobuf::io::FileInputStream fs(fd);
			google::protobuf::TextFormat::Parse(&fs, &is);
			close(fd);
		}
		else
		{
			std::cout << "could not open file " << path << std::endl;
		}
	}

	ListContainersResponse lc;
	{
		const std::string path = pb_prefix + "_listcontainers.pb";
		int fd = open(path.c_str(), O_RDONLY);
		if (fd >= 0)
		{
			google::protobuf::io::FileInputStream fs(fd);
			google::protobuf::TextFormat::Parse(&fs, &lc);
			close(fd);
		}
		else
		{
			std::cout << "could not open file " << path << std::endl;
		}
	}

	FakeCRIServer service(delay_us, std::move(cs), std::move(ps), std::move(lc), runtime);
	FakeCRIImageServer image_service(std::move(is));

	grpc::ServerBuilder builder;
	builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	builder.RegisterService(&image_service);
	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
	server->Wait();

	return 0;
}
