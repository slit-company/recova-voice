"use client";

import { AssignedNumbersBinder } from "@/components/telephony/AssignedNumbersBinder";

export default function TelephonyNumbersPage() {
  return (
    <div className="container mx-auto px-4 py-8 space-y-6">
      <AssignedNumbersBinder />
    </div>
  );
}
