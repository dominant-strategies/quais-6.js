import fs from "fs";
import { resolve } from "./path.js";
export function getChanges() {
    const changes = [
        { title: "", version: "null", body: [] }
    ];
    const content = fs.readFileSync(resolve("CHANGELOG.md")).toString();
    for (const line of content.split("\n")) {
        let match = line.match(/^quais\/v(\S+)\s/);
        if (match) {
            changes.push({ version: match[1], title: line.trim(), body: [] });
        }
        else {
            const l = line.trim();
            if (l && !l.match(/^-+$/)) {
                changes[changes.length - 1].body.push(l);
            }
        }
    }
    changes.shift();
    return changes;
}
//# sourceMappingURL=changelog.js.map