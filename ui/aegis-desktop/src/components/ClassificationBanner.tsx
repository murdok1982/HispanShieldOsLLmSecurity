import React from 'react';

interface Props {
  classification: string;
}

export default function ClassificationBanner({ classification }: Props) {
  return (
    <div className="fixed w-full flex items-center justify-center font-bold tracking-widest uppercase z-[10000]" style={{
      height: '24px',
      backgroundColor: '#FF3B30',
      color: '#FFFFFF',
      fontSize: '12px'
    }}>
      {classification}
    </div>
  );
}
