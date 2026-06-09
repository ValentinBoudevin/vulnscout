import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';

import DropdownMenu from '../../src/components/DropdownMenu';

describe('DropdownMenu', () => {
    const items = [
        { label: 'Edit', onClick: jest.fn() },
        { label: 'Delete', onClick: jest.fn() },
    ];

    beforeEach(() => {
        jest.restoreAllMocks();
        items.forEach((item) => item.onClick.mockReset());
    });

    const mockButtonPosition = (rect: Partial<DOMRect>, innerHeight: number) => {
        Object.defineProperty(window, 'innerHeight', {
            configurable: true,
            value: innerHeight,
        });

        jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            top: 0,
            right: 0,
            bottom: 0,
            left: 0,
            toJSON: () => {},
            ...rect,
        } as DOMRect);
    };

    it('opens the menu, invokes an item and closes it again', async () => {
        const user = userEvent.setup();
        render(<DropdownMenu items={items} />);

        await user.click(screen.getByRole('button', { name: /actions menu/i }));
        await user.click(screen.getByText('Edit'));

        expect(items[0].onClick).toHaveBeenCalledTimes(1);
        expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });

    it('closes when clicking outside the portal', async () => {
        const user = userEvent.setup();
        render(<DropdownMenu items={items} />);

        await user.click(screen.getByRole('button', { name: /actions menu/i }));
        expect(screen.getByText('Delete')).toBeInTheDocument();

        await user.click(document.body);
        expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });

    it('positions the menu above the button when space below is limited', async () => {
        const user = userEvent.setup();
        mockButtonPosition({ top: 250, bottom: 290, right: 400 }, 320);
        render(<DropdownMenu items={items} />);

        await user.click(screen.getByRole('button', { name: /actions menu/i }));

        const menu = document.body.querySelector('div.fixed') as HTMLElement;
        expect(menu).toHaveStyle({ top: '154px' });
    });

    it('positions the menu below the button when there is enough space', async () => {
        const user = userEvent.setup();
        mockButtonPosition({ top: 50, bottom: 70, right: 240 }, 900);
        render(<DropdownMenu items={items} />);

        await user.click(screen.getByRole('button', { name: /actions menu/i }));

        const menu = document.body.querySelector('div.fixed') as HTMLElement;
        expect(menu).toHaveStyle({ top: '74px' });
    });
});
