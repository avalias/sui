// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Disclosure } from '@headlessui/react';
import { ChevronDown24 } from '@mysten/icons';
import { cva } from 'class-variance-authority';

import type { ReactNode } from 'react';

export type DisclosureBoxProps = {
    defaultOpen?: boolean;
    title: ReactNode;
    children: ReactNode;
    variant: 'inline' | 'accordion';
};

const disclosureStyles = cva('', {
    variants: {
        display: {
            accordion: 'rounded-lg bg-gray-40',
            inline: '',
        },
    },
});

const buttonStyles = cva('flex cursor-pointer select-none', {
    variants: {
        display: {
            inline: 'gap-1 items-center text-p1 flex ui-open:pb-3.5 text-hero-dark font-normal',
            accordion:
                'flex-nowrap items-center py-3.75 px-5 justify-between text-body text-gray-90 font-semibold',
        },
    },
});

const panelStyles = cva('', {
    variants: {
        display: {
            inline: 'bg-gray-40 rounded-lg p-5',
            accordion: 'py-3.75 px-5',
        },
    },
});

export function DisclosureBox({
    defaultOpen,
    title,
    children,
    variant,
}: DisclosureBoxProps) {
    return (
        <Disclosure
            as="div"
            className={disclosureStyles({ display: variant })}
            defaultOpen={defaultOpen}
        >
            <Disclosure.Button
                as="div"
                className={buttonStyles({ display: variant })}
            >
                {title}
                <ChevronDown24 className="-rotate-90 text-steel ui-open:rotate-0" />
            </Disclosure.Button>
            <Disclosure.Panel className={panelStyles({ display: variant })}>
                {children}
            </Disclosure.Panel>
        </Disclosure>
    );
}
