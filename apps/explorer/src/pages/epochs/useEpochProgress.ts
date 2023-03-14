// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useTimeAgo } from '@mysten/core';

export function useEpochProgress(
    start: number = 0,
    duration: number = 0,
    suffix: string = 'left'
) {
    const end = start + duration;
    const time = useTimeAgo(end);
    const progress =
        start && duration
            ? Math.min(((Date.now() - start) / (end - start)) * 100, 100)
            : 0;

    return {
        progress,
        label: `${time} ${suffix}`,
    };
}
