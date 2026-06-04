import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

import VersionsLine, { type version } from '../../src/components/VersionsLine';

describe('VersionsLine', () => {
    const versions: version[] = [
        { title: '1.0', highlight: 'alpha', details: 'first release', left_color: 'bg-red-500' },
        { title: '2.0', details: 'second release' },
        { title: '3.0' },
    ];

    it('renders the version markers, labels and details', () => {
        const { container } = render(<VersionsLine versions={versions} />);

        expect(screen.getByText('1.0')).toBeInTheDocument();
        expect(screen.getByText('alpha')).toBeInTheDocument();
        expect(screen.getByText('first release')).toBeInTheDocument();
        expect(screen.getByText('2.0')).toBeInTheDocument();
        expect(screen.getByText('second release')).toBeInTheDocument();
        expect(screen.getByText('3.0')).toBeInTheDocument();
        expect(container.querySelector('.bg-red-500')).toBeInTheDocument();
    });

    it('switches to the compact label sizes when reduce_size is true', () => {
        const { container } = render(<VersionsLine versions={versions} reduce_size />);

        expect(screen.getByText('1.0')).toHaveClass('text-sm');
        expect(container.querySelector('.text-xs')).toBeInTheDocument();
    });
});
