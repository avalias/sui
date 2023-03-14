// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import TransportWebHID from '@ledgerhq/hw-transport-webhid';
import TransportWebUSB from '@ledgerhq/hw-transport-webusb';
import SuiLedgerClient from '@mysten/ledgerjs-hw-app-sui';
import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useState,
} from 'react';

import { LedgerSigner } from '../../LedgerSigner';
import { api } from '../../redux/store/thunk-extras';
import {
    LedgerConnectionFailedError,
    LedgerNoTransportMechanismError,
} from './LedgerExceptions';

import type Transport from '@ledgerhq/hw-transport';

type SuiLedgerClientProviderProps = {
    children: React.ReactNode;
};

type SuiLedgerClientContextValue = {
    suiLedgerClient: SuiLedgerClient | undefined;
    connectToLedger: () => Promise<SuiLedgerClient>;
    initializeLedgerSignerInstance: (
        derivationPath: string
    ) => Promise<LedgerSigner>;
};

const SuiLedgerClientContext = createContext<
    SuiLedgerClientContextValue | undefined
>(undefined);

export function SuiLedgerClientProvider({
    children,
}: SuiLedgerClientProviderProps) {
    const [suiLedgerClient, setSuiLedgerClient] = useState<SuiLedgerClient>();

    useEffect(() => {
        const onDisconnect = () => {
            setSuiLedgerClient(undefined);
        };

        suiLedgerClient?.transport.on('disconnect', onDisconnect);
        return () => suiLedgerClient?.transport.off('disconnect', onDisconnect);
    }, [suiLedgerClient?.transport]);

    const initializeLedgerSignerInstance = useCallback(
        async (derivationPath: string) => {
            if (!suiLedgerClient) {
                try {
                    const transport = await getLedgerTransport();
                    const newClient = new SuiLedgerClient(transport);
                    setSuiLedgerClient(newClient);

                    return new LedgerSigner(
                        newClient,
                        derivationPath,
                        api.instance.fullNode
                    );
                } catch (error) {
                    throw new Error('F');
                }
            }

            return new LedgerSigner(
                suiLedgerClient,
                derivationPath,
                api.instance.fullNode
            );
        },
        [suiLedgerClient]
    );

    const connectToLedger = useCallback(async () => {
        if (suiLedgerClient?.transport) {
            // If we've already connected to a Ledger device, we need
            // to close the connection before we try to re-connect
            await suiLedgerClient.transport.close();
        }

        const ledgerTransport = await getLedgerTransport(true);
        const ledgerClient = new SuiLedgerClient(ledgerTransport);
        setSuiLedgerClient(ledgerClient);
        return ledgerClient;
    }, [suiLedgerClient]);

    const contextValue: SuiLedgerClientContextValue = useMemo(() => {
        return {
            suiLedgerClient,
            connectToLedger,
            initializeLedgerSignerInstance,
        };
    }, [connectToLedger, suiLedgerClient, initializeLedgerSignerInstance]);

    return (
        <SuiLedgerClientContext.Provider value={contextValue}>
            {children}
        </SuiLedgerClientContext.Provider>
    );
}

export function useSuiLedgerClient() {
    const suiLedgerClientContext = useContext(SuiLedgerClientContext);
    if (!suiLedgerClientContext) {
        throw new Error(
            'useSuiLedgerClient use must be within SuiLedgerClientContext'
        );
    }
    return suiLedgerClientContext;
}

async function getLedgerTransport(requestPermissionsFirst = false) {
    let ledgerTransport: Transport | null | undefined;

    try {
        if (requestPermissionsFirst) {
            ledgerTransport = await requestConnectToLedger();
        } else {
            ledgerTransport = await forceConnectToLedger();
        }
    } catch (error) {
        throw new LedgerConnectionFailedError(
            "Unable to connect to the user's Ledger device"
        );
    }

    if (!ledgerTransport) {
        throw new LedgerNoTransportMechanismError(
            "There are no supported transport mechanisms to connect to the user's Ledger device"
        );
    }

    return ledgerTransport;
}

async function requestConnectToLedger(): Promise<Transport | null> {
    if (await TransportWebHID.isSupported()) {
        return await TransportWebHID.request();
    } else if (await TransportWebUSB.isSupported()) {
        return await TransportWebUSB.request();
    }
    return null;
}

async function forceConnectToLedger(): Promise<Transport | null> {
    if (await TransportWebHID.isSupported()) {
        return await TransportWebHID.openConnected();
    } else if (await TransportWebUSB.isSupported()) {
        return await TransportWebUSB.openConnected();
    }
    return null;
}
