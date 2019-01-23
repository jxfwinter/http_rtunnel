#include "kconfig.h"
#include "manager.h"
#include "fiber_frame_context.hpp"
#include <iostream>

int main(int argc,char ** argv)
{
    try
    {
        FiberFrameContext& frame_cxt = FiberFrameContext::instance();
        frame_cxt.run_thread_count = 3;
        frame_cxt.init();

        ConfigParams& params = ConfigParams::instance();
        //初始化
        if(!params.init(argc, argv))
        {
            return 1;
        }

        init_logging(params.log_path, params.log_level);

        Manager mgr;
        mgr.start();

        frame_cxt.wait();
    }
    catch(std::exception const &e)
    {
        std::cerr << "exit! unhandled exception: " << e.what() << std::endl;
    }
    return 0;
}
