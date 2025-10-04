import React from 'react';
import { UserIcon } from '@heroicons/react/24/outline';

const ProfilePage = () => {
  return (
    <div className="text-center py-12">
      <UserIcon className="mx-auto h-12 w-12 text-gray-400" />
      <h1 className="mt-2 text-3xl font-bold text-gray-900">User Profile</h1>
      <p className="mt-4 text-lg text-gray-600">
        Manage your profile settings and preferences. This feature is coming soon!
      </p>
    </div>
  );
};

export default ProfilePage;
