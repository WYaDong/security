// -*- coding: utf-8 -*-
// Project    : Security
// File       : HiLogUtils.ets
// Time       ：2024/3/20
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import hilog from '@ohos.hilog'

export class HiLogUtils {
  private static _code: number = 0x1111
  private static _tag: string = 'Security'

  static debug(msg: String) {
    hilog.debug(HiLogUtils._code, HiLogUtils._tag, '%{public}s', msg)
  }

  static info(msg: String) {
    hilog.info(HiLogUtils._code, HiLogUtils._tag, '%{public}s', msg)
  }

  static warn(msg: String) {
    hilog.warn(HiLogUtils._code, HiLogUtils._tag, '%{public}s', msg)
  }

  static error(msg: String) {
    hilog.error(HiLogUtils._code, HiLogUtils._tag, '%{public}s', msg)
  }

  static log(enable: boolean, msg: String) {
    if (enable) {
      hilog.info(HiLogUtils._code, HiLogUtils._tag, '%{public}s', " ☘️☘️ :  " + msg)
    }
  }
}