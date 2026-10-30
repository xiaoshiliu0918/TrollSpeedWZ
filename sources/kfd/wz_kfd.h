//
//  wz_kfd.h
//  TrollSpeedWZ
//
//  kfd 内核读写 + 跨进程 attach 的实验入口。
//  只在 HUD 进程（带 -hud 参数）里跑，主 App 不触发。
//

#import <Foundation/Foundation.h>

/// 是否已经探测过（用于 HUD 决定显示调试文本还是网速）
BOOL WZProbeEnabled(void);

/// 当前探测状态，短字符串，直接塞进悬浮窗
NSString *WZProbeStatus(void);

/// 启动后台探测线程（幂等）
void WZProbeStart(void);
