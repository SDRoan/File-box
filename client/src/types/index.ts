export interface User {
  id: string;
  email: string;
  name: string;
  storageUsed: number;
  storageLimit: number;
}

export interface FileItem {
  _id: string;
  name: string;
  originalName: string;
  path: string;
  size: number;
  mimeType: string;
  owner: User | string;
  parentFolder: string | null;
  isFolder: boolean;
  isStarred: boolean;
  isTrashed: boolean;
  deletedAt?: string | null;
  recoveryPeriodDays?: number;
  dataClassification?: 'Public' | 'Internal' | 'Confidential' | 'Top Secret';
  encryptionEnabled?: boolean;
  watermarkEnabled?: boolean;
  createdAt: string;
  updatedAt: string;
}

// Alias for convenience
export type FileItemType = FileItem;

export interface Folder {
  _id: string;
  name: string;
  owner: User | string;
  parentFolder: string | null;
  isStarred: boolean;
  isTrashed: boolean;
  deletedAt?: string | null;
  recoveryPeriodDays?: number;
  dataClassification?: 'Public' | 'Internal' | 'Confidential' | 'Top Secret';
  encryptionEnabled?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Share {
  _id: string;
  shareId: string;
  file: FileItem;
  owner: User;
  accessType: 'view' | 'edit';
  password?: string;
  expiresAt?: string;
  downloadCount: number;
  createdAt: string;
}

