//
//  wz_kfd.h
//  TrollSpeedWZ
//
//  kfd 内核读写 + 跨进程 attach 的实验入口。
//  只在 HUD 进程（带 -hud 参数）里跑，主 App 不触发。
//

#import <Foundation/Foundation.h>

// 关键：HUDRootViewController.mm 是 ObjC++，若不加 extern "C"，
// 这里的声明会按 C++ 规则改名，而 wz_kfd.m 按 C 编译，链接时符号对不上。
#ifdef __cplusplus
extern "C" {
#endif

/// 是否已经进入调试显示模式
BOOL WZProbeEnabled(void);

/// 当前探测状态，短字符串，直接塞进悬浮窗
NSString *WZProbeStatus(void);

/// 启动后台探测线程（幂等）
void WZProbeStart(void);

#ifdef __cplusplus
}
#endif
