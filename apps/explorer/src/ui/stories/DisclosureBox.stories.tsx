// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type Meta, type StoryObj } from '@storybook/react';

import { DisclosureBox, type DisclosureBoxProps } from '../DisclosureBox';
import { Text } from '../Text';

export default {
    component: DisclosureBox,
} as Meta;

export const DisclosureBoxDefault: StoryObj<DisclosureBoxProps> = {
    render: (props) => (
        <DisclosureBox {...props}>
            <Text variant="bodySmall/normal">Test content</Text>
        </DisclosureBox>
    ),
    args: { title: 'Closed by default', variant: 'accordion' },
};

export const DisclosureBoxClosed: StoryObj<DisclosureBoxProps> = {
    ...DisclosureBoxDefault,
    args: {
        title: 'Expanded disclosure box',
        defaultOpen: true,
        variant: 'accordion',
    },
};

export const InlineDisclosureBox: StoryObj<DisclosureBoxProps> = {
    ...DisclosureBoxDefault,
    args: { title: 'Inline Disclosure', variant: 'inline' },
};
