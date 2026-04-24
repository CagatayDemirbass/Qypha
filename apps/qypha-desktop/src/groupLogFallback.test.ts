import { describe, expect, it } from "vitest";
import { collectLegacyGroupLogFallback } from "./groupLogFallback";

describe("collectLegacyGroupLogFallback", () => {
  it("creates a group conversation from mailbox join and incoming logs", () => {
    const logs = [
      "Group invite joined: group1 (grp_a100a3a207f649bfa029892b9282209f)",
      "Mailbox: mailbox-backed group session registered with encrypted-disk persistence. No peer dial was attempted.",
      "[group1] agent1 joined as did:nxf:91081063299cb6bd88e860c4132766d233576ee42d3c41b338a7c33cdf4b0009",
      "[group1] agent4 joined as did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b",
      "[group1] agent1 (did:nxf:91081063299cb6bd88e860c4132766d233576ee42d3c41b338a7c33cdf4b0009) hey"
    ];

    const result = collectLegacyGroupLogFallback({
      logs,
      initialSyntheticTs: 10
    });

    expect(result.seeds).toEqual([
      {
        groupId: "grp_a100a3a207f649bfa029892b9282209f",
        groupLabel: "group1"
      }
    ]);
    expect(result.entries.map((entry) => ({
      sender: entry.sender,
      text: entry.text
    }))).toEqual([
      { sender: "system", text: "joined mailbox group" },
      { sender: "system", text: "member joined • agent1" },
      { sender: "system", text: "member joined • agent4" },
      {
        sender: "agent1 (did:nxf:91081063299cb6bd88e860c4132766d233576ee42d3c41b338a7c33cdf4b0009)",
        text: "hey"
      }
    ]);
  });

  it("deduplicates local group send echo lines", () => {
    const logs = [
      "Group invite joined: group1 (grp_localtest0000000000000000000000000001)",
      "> /sendto grp_localtest0000000000000000000000000001 hello team",
      "[group1] agent4 (did:nxf:971800adc12789468c09a999cfa97609858b29b19cac8d2754a55550624ea47b) hello team",
      "[group1] agent1 (did:nxf:91081063299cb6bd88e860c4132766d233576ee42d3c41b338a7c33cdf4b0009) hello back"
    ];

    const result = collectLegacyGroupLogFallback({
      logs,
      initialSyntheticTs: 50
    });

    expect(result.entries.map((entry) => entry.text)).toEqual([
      "joined mailbox group",
      "hello back"
    ]);
  });
});
