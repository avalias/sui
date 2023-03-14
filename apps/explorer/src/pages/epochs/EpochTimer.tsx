// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEpochProgress } from './useEpochProgress';

import { useGetSystemObject } from '~/hooks/useGetObject';
import { ProgressCircle } from '~/ui/ProgressCircle';
import { Text } from '~/ui/Text';

export function EpochTimer() {
    // todo: replace this call when we have an endpoint for querying current epoch
    const { data } = useGetSystemObject();

    const { progress, label } = useEpochProgress(
        data?.epochStartTimestampMs,
        data?.epochDurationMs
    );

    return (
        <div className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-gray-45 py-2 px-2.5 shadow-notification">
            <div className="w-5 text-steel-darker">
                <ProgressCircle progress={progress} />
            </div>
            <Text variant="p2/medium" color="steel-darker">
                Epoch {data?.epoch} in progress. {label}
            </Text>
        </div>
    );
}
