"use client";

import { AssignedNumbersBinder } from "@/components/telephony/AssignedNumbersBinder";

export default function TelephonyNumbersPage() {
  return (
    <div className="container mx-auto px-4 py-8 space-y-6">
      <AssignedNumbersBinder
        title="Assigned phone numbers"
        description="Recova-managed numbers assigned to your organization. Bind a number to an inbound workflow without exposing carrier credentials."
      />
    </div>
  );
}
