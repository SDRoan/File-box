import React from 'react';
import './FileSortFilter.css';

type SortOption = 'name' | 'date' | 'size' | 'type';
type SortOrder = 'asc' | 'desc';
type FilterOption = 'all' | 'images' | 'videos' | 'documents' | 'folders';

interface FileSortFilterProps {
  sortBy: SortOption;
  sortOrder: SortOrder;
  filterBy: FilterOption;
  viewMode: 'grid' | 'list';
  onSortChange: (sort: SortOption) => void;
  onSortOrderChange: (order: SortOrder) => void;
  onFilterChange: (filter: FilterOption) => void;
  onViewModeChange: (mode: 'grid' | 'list') => void;
}

const FileSortFilter: React.FC<FileSortFilterProps> = ({
  sortBy,
  sortOrder,
  filterBy,
  viewMode,
  onSortChange,
  onSortOrderChange,
  onFilterChange,
  onViewModeChange,
}) => {
  return (
    <div className="file-sort-filter">
      <div className="filter-group">
        <label>Filter:</label>
        <select value={filterBy} onChange={(e) => onFilterChange(e.target.value as FilterOption)} className="filter-select">
          <option value="all">All Files</option>
          <option value="folders">Folders Only</option>
          <option value="images">Images</option>
          <option value="videos">Videos</option>
          <option value="documents">Documents</option>
        </select>
      </div>

      <div className="filter-group">
        <label>Sort by:</label>
        <select value={sortBy} onChange={(e) => onSortChange(e.target.value as SortOption)} className="filter-select">
          <option value="name">Name</option>
          <option value="date">Date</option>
          <option value="size">Size</option>
          <option value="type">Type</option>
        </select>
      </div>

      <button
        onClick={() => onSortOrderChange(sortOrder === 'asc' ? 'desc' : 'asc')}
        className="sort-order-btn"
        title={`Sort ${sortOrder === 'asc' ? 'Descending' : 'Ascending'}`}
      >
        {sortOrder === 'asc' ? '↑' : '↓'}
      </button>

      <div className="view-toggle">
        <button
          onClick={() => onViewModeChange('grid')}
          className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
          title="Grid View"
        >
          ⊞
        </button>
        <button
          onClick={() => onViewModeChange('list')}
          className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}
          title="List View"
        >
          ☰
        </button>
      </div>
    </div>
  );
};

export default FileSortFilter;
export type { SortOption, SortOrder, FilterOption };










