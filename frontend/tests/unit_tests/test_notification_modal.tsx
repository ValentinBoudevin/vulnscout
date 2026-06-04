import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import NotificationModal, { type Notification } from '../../src/components/NotificationModal';

describe('NotificationModal', () => {
    const baseNotification = {
        level: 'warning',
        title: 'Check the scan results',
        message: 'A vulnerability requires attention.',
        action: 'Run vulnscout --refresh',
    } satisfies Notification;

    it.each([
        ['warning', 'text-yellow-400', 'border-yellow-500'],
        ['error', 'text-red-400', 'border-red-500'],
        ['info', 'text-cyan-300', 'border-cyan-500'],
    ] as const)('renders the %s style variant', (level, labelClass, borderClass) => {
        render(<NotificationModal notification={{ ...baseNotification, level }} />);

        expect(screen.getByText(level)).toHaveClass(labelClass);
        expect(document.body.querySelector(`.${borderClass}`)).toBeInTheDocument();
        expect(screen.getByText(baseNotification.title)).toBeInTheDocument();
        expect(screen.getByText(baseNotification.message)).toBeInTheDocument();
        expect(screen.getByText(baseNotification.action as string)).toBeInTheDocument();
    });

    it('omits the action box when no action is provided', () => {
        render(<NotificationModal notification={{ ...baseNotification, action: undefined }} />);

        expect(screen.queryByText(baseNotification.action as string)).not.toBeInTheDocument();
    });
});
