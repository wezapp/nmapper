// DOMParser minimal pour tester parseNmapXML sans dépendances.
// Supporte uniquement les sélecteurs utilisés par file-processor.js :
//   - tagname  (ex: 'host', 'port', 'state')
//   - tagname[attr="val"]  (ex: 'address[addrtype="ipv4"]')

class MockElement {
    constructor(tag, attrs) {
        this.tagName = tag.toLowerCase();
        this._attrs = attrs;
        this.children = [];
    }

    getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this._attrs, name)
            ? this._attrs[name]
            : null;
    }

    querySelector(selector) {
        return this._walk(selector, true);
    }

    querySelectorAll(selector) {
        const results = [];
        this._walkAll(selector, results);
        return results;
    }

    _matches(selector) {
        const m = selector.match(/^(\w+)\[(\w[\w-]*)="([^"]*)"\]$/);
        if (m) return this.tagName === m[1].toLowerCase() && this.getAttribute(m[2]) === m[3];
        return this.tagName === selector.toLowerCase();
    }

    _walk(selector, single) {
        for (const child of this.children) {
            if (child._matches(selector)) return child;
            const found = child._walk(selector, single);
            if (found) return found;
        }
        return null;
    }

    _walkAll(selector, acc) {
        for (const child of this.children) {
            if (child._matches(selector)) acc.push(child);
            child._walkAll(selector, acc);
        }
    }
}

function parseAttrs(str) {
    const attrs = {};
    const re = /([\w-]+)="([^"]*)"/g;
    let m;
    while ((m = re.exec(str)) !== null) attrs[m[1]] = m[2];
    return attrs;
}

function parseXML(xml) {
    const root = new MockElement('#document', {});
    const stack = [root];
    const re = /<(\/?)(\w[\w-]*)((?:\s[^>]*?)?)\s*(\/?)>/g;
    let m;
    while ((m = re.exec(xml)) !== null) {
        const [, closing, tag, attrStr, selfClose] = m;
        if (closing) {
            if (stack.length > 1) stack.pop();
        } else {
            const el = new MockElement(tag, parseAttrs(attrStr));
            stack[stack.length - 1].children.push(el);
            if (!selfClose) stack.push(el);
        }
    }
    return root;
}

export class MockDOMParser {
    parseFromString(xmlStr) {
        return parseXML(xmlStr);
    }
}
