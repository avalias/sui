// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { activeAddressSelector } from '../redux/slices/account';
import useAppSelector from './useAppSelector';

export function useActiveAddress() {
<<<<<<< HEAD
    return useAppSelector(activeAddressSelector);
=======
    return useAppSelector(activeAddressSelector) ?? null;
>>>>>>> dc173718b (work)
}
