#!/usr/bin/env python3
"""
3BDEEN Telegram Bot v3 - محسّن مع blacklist
"""

import re
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters
)

BOT_TOKEN = "8627842696:AAGBimoLzf6kBCz98K9zP-XjN1Ut1ypmupY"
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)


class DumpAnalyzer:
    def __init__(self):
        self.event_senders = [
            'send', 'report', 'track', 'log', 'post', 'submit',
            'analytics', 'event', 'emit', 'dispatch', 'trigger',
            'notify', 'publish', 'broadcast', 'flush', 'record'
        ]

        # namespaces يتم تجاهلها تماماً
        self.blacklist = [
            'system.', 'unityengine.ui', 'unityengine.event',
            'unityengine.uielements', 'unityengine.input',
            'unityengine.video', 'unityengine.audio',
            'unityengine.rendering', 'unityengine.animation',
            'unityengine.physics', 'unityengine.network',
            'system.threading', 'system.diagnostics',
            'system.collections', 'system.reflection',
            'system.runtime', 'system.text', 'system.io',
            'system.net', 'system.linq', 'system.xml',
            'system.security', 'system.globalization',
            'microsoft.', 'mono.', 'unityeditor.',
        ]

        self.filters = {
            "level": [
                'level', 'chapter', 'stage', 'wave', 'castle',
                'dungeon', 'floor', 'round', 'mission', 'quest',
                'map', 'zone', 'world', 'episode', 'act',
            ],
            "ads": [
                'ad', 'ads', 'rewarded', 'interstitial', 'banner',
                'offerwall', 'mediation', 'admob', 'ironsource',
                'applovin', 'impression', 'watched',
            ],
            "purchase": [
                'purchase', 'iap', 'buy', 'transaction', 'payment',
                'shop', 'store', 'product', 'receipt', 'order',
                'checkout', 'subscription', 'premium', 'gem', 'coin',
                'currency', 'spend', 'consume',
            ],
            "network": [
                'http', 'request', 'response', 'download', 'upload',
                'fetch', 'connect', 'socket', 'api', 'endpoint', 'sync',
            ],
            "crypto": [
                'encrypt', 'decrypt', 'hash', 'sign', 'verify',
                'cipher', 'aes', 'rsa', 'md5', 'sha', 'hmac', 'base64',
            ],
            "auth": [
                'login', 'auth', 'token', 'session', 'jwt', 'oauth',
                'register', 'logout', 'signin', 'signup', 'credential',
            ],
            "events": [
                'adjust', 'appsflyer', 'firebase', 'amplitude', 'mixpanel',
                'devtodev', 'gameanalytics', 'complete', 'completed',
                'finish', 'finished', 'reached', 'achieved', 'unlocked',
                'win', 'won', 'lose', 'lost', 'failed', 'success', 'event',
            ],
        }

        self.raw_results = []
        self.all_methods = []
        self.tokens_found = []
        self.classes = {}
        self.filename = ""

    def _is_blacklisted(self, class_name: str) -> bool:
        cn = class_name.lower()
        return any(cn.startswith(b) for b in self.blacklist)

    def _is_event_sender(self, method_name: str, class_name: str) -> bool:
        mn = method_name.lower()
        cn = class_name.lower()
        if any(k in mn for k in self.event_senders):
            return True
        if 'event' in mn:
            return True
        if any(k in cn for k in ['analytics', 'tracker', 'telemetry',
                                   'adjust', 'appsflyer', 'firebase',
                                   'gameanalytics', 'devtodev']):
            return True
        return False

    def analyze(self, content: str, filename: str = ""):
        self.raw_results = []
        self.all_methods = []
        self.tokens_found = []
        self.classes = {}
        self.filename = filename

        lh, cc, ch = "0x0", "Unknown", "0x0"

        for line in content.splitlines():
            hex_m = re.search(r'//\s+(0x[0-9A-Fa-f]+)', line)
            if hex_m:
                lh = hex_m.group(1)

            cls_m = re.search(r'(?:^|\s)class\s+([\w\.]+)', line)
            if cls_m:
                cc, ch = cls_m.group(1), lh
                if cc not in self.classes:
                    self.classes[cc] = []

            method_info = None
            patterns = [
                r'(?:public|private|protected|internal|static)[\w\s]+?\s+([\w_]+)\s*\((.*?)\)',
                r'System\.Void\s+([\w_]+)\s*\((.*?)\);',
                r'([\w\.]+)\s+([\w_]+)\s*\((.*?)\)\s*//\s*(0x[0-9A-Fa-f]+)',
            ]
            for pat in patterns:
                m = re.search(pat, line)
                if m:
                    mn = m.group(1)
                    if mn in ('class', 'void', 'return', 'new', 'if',
                               'else', 'for', 'while', 'true', 'false'):
                        continue
                    params = m.group(2) if len(m.groups()) >= 2 else ""
                    method_info = {
                        "ch": ch, "cn": cc, "mh": lh,
                        "mn": mn, "params": params,
                        "line": line.strip()
                    }
                    break

            if method_info:
                self.all_methods.append(method_info)
                if cc in self.classes:
                    self.classes[cc].append(method_info)
                if (not self._is_blacklisted(cc) and
                        self._is_event_sender(method_info['mn'], method_info['cn'])):
                    self.raw_results.append(method_info)

            tok_m = re.search(
                r'string\s+([\w_]*(?:token|key|sig|secret|api|auth)[\w_]*)\s*=\s*"([^"]{4,})"',
                line, re.I)
            if tok_m:
                self.tokens_found.append({"n": tok_m.group(1), "v": tok_m.group(2)})

        return len(self.raw_results), len(self.tokens_found), len(self.classes)

    def get_filtered(self, f_type=None, query="") -> list:
        # بحث حر
        if query:
            q = query.lower()
            return [m for m in self.all_methods
                    if not self._is_blacklisted(m['cn']) and
                    (q in m['mn'].lower() or q in m['cn'].lower())]

        # فلتر محدد
        if f_type and f_type in self.filters:
            ks = self.filters[f_type]
            results = []
            seen = set()

            for m in self.all_methods:
                key = (m['cn'], m['mn'])
                if key in seen:
                    continue

                # تجاهل الـ blacklisted namespaces
                if self._is_blacklisted(m['cn']):
                    continue

                mn_low = m['mn'].lower()

                # الكلمة لازم تكون في اسم الـ method نفسها فقط
                if any(k.lower() in mn_low for k in ks):
                    results.append(m)
                    seen.add(key)

            # ترتيب: الأهم أول
            priority = ['send', 'track', 'log', 'report', 'emit',
                        'event', 'complete', 'finish', 'win', 'reached']
            results.sort(key=lambda m: 0 if any(p in m['mn'].lower() for p in priority) else 1)
            return results

        return self.raw_results

    def generate_hook(self, item: dict, tool: str) -> str:
        off, mn, cn = item['mh'], item['mn'], item['cn']
        params = item.get('params', '')
        param_list = [p.strip() for p in params.split(',') if p.strip()]
        param_logs = "\n".join([
            f"        console.log('  arg[{i}]: ' + args[{i}]);"
            for i in range(min(len(param_list), 5))
        ]) or "        // no parameters"

        if tool == "frida":
            return (
                f"// 3BDEEN Hook\n// Class:  {cn}\n// Method: {mn}\n// Offset: {off}\n\n"
                f"var lib = Process.getModuleByName('libil2cpp.so').base;\n\n"
                f"Interceptor.attach(lib.add({off}), {{\n"
                f"    onEnter: function(args) {{\n"
                f"        console.log('[3BDEEN] >>> {mn}');\n"
                f"{param_logs}\n"
                f"    }},\n"
                f"    onLeave: function(retval) {{\n"
                f"        console.log('[3BDEEN] <<< retval: ' + retval);\n"
                f"        // retval.replace(1);\n"
                f"    }}\n"
                f"}});\nconsole.log('[3BDEEN] Hooked: {mn} @ {off}');"
            )
        elif tool == "frida_block":
            return (
                f"// 3BDEEN Block\nvar lib = Process.getModuleByName('libil2cpp.so').base;\n\n"
                f"Interceptor.attach(lib.add({off}), {{\n"
                f"    onEnter: function(args) {{ console.log('[3BDEEN] BLOCKED: {mn}'); }},\n"
                f"    onLeave: function(retval) {{ retval.replace(0); }}\n"
                f"}});"
            )
        elif tool == "gg":
            return f"-- GameGuardian\n-- {cn}.{mn}\nre = {{address=lib+{off}, flags=4, value='RET'}}"
        elif tool == "libtool":
            return f'HOOK("{off}", new_{mn}, old_{mn});'
        return ""

    def format_results(self, items, max_items=20) -> str:
        if not items:
            return "❌ مفيش نتائج."
        lines = []
        for i in items[:max_items]:
            lines.append(f"📦 `{i['cn']}`")
            lines.append(f"┗ 🔧 `{i['mn']}`")
            if i.get('params'):
                p = i['params'][:50] + ('...' if len(i['params']) > 50 else '')
                lines.append(f"   📝 `{p}`")
            lines.append(f"   📍 `{i['mh']}`")
            lines.append("")
        if len(items) > max_items:
            lines.append(f"_... و {len(items) - max_items} نتيجة أخرى_")
        return "\n".join(lines)

    def get_stats(self) -> str:
        return (
            f"📊 *إحصائيات:*\n"
            f"• Classes: `{len(self.classes)}`\n"
            f"• Total Methods: `{len(self.all_methods)}`\n"
            f"• Event Senders: `{len(self.raw_results)}`\n"
            f"• Tokens/Keys: `{len(self.tokens_found)}`\n"
        )


# ========== State ==========
user_analyzers: dict[int, DumpAnalyzer] = {}
user_results: dict[int, list] = {}


def get_analyzer(uid: int) -> DumpAnalyzer:
    if uid not in user_analyzers:
        user_analyzers[uid] = DumpAnalyzer()
    return user_analyzers[uid]


def main_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📋 Trackers",    callback_data="f_trackers"),
            InlineKeyboardButton("🔑 Tokens",      callback_data="f_tokens"),
        ],
        [
            InlineKeyboardButton("🎮 Level/Stage", callback_data="f_level"),
            InlineKeyboardButton("📺 Ads",         callback_data="f_ads"),
            InlineKeyboardButton("💵 Purchase",    callback_data="f_purchase"),
        ],
        [
            InlineKeyboardButton("🎯 Events",      callback_data="f_events"),
            InlineKeyboardButton("🌐 Network",     callback_data="f_network"),
            InlineKeyboardButton("🔐 Crypto",      callback_data="f_crypto"),
        ],
        [
            InlineKeyboardButton("📊 Stats",       callback_data="f_stats"),
            InlineKeyboardButton("🔍 بحث",         callback_data="f_search"),
        ],
    ])


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "```\n╔══════════════════════════════╗\n"
        "║   3BDEEN MOBILE ANALYZER     ║\n"
        "║   [ SYSTEM ONLINE ]  v3.0    ║\n"
        "╚══════════════════════════════╝\n```\n"
        "ابعتلي ملف `dump.cs` وأنا أحلله!\n\n"
        "📋 `/trackers` — Event senders\n"
        "🔑 `/tokens` — Keys & Tokens\n"
        "🎮 `/level` — Level/Stage/Chapter\n"
        "📺 `/ads` — Ads events\n"
        "💵 `/purchase` — Purchase events\n"
        "🎯 `/events` — Complete/Finish/Win\n"
        "🌐 `/network` — Network calls\n"
        "🔐 `/crypto` — Crypto methods\n"
        "📊 `/stats` — Statistics\n"
        "🔍 `/search كلمة` — بحث حر\n"
        "🗑 `/clear` — مسح البيانات",
        parse_mode="Markdown"
    )


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    doc = update.message.document
    if not doc:
        await update.message.reply_text("❌ ابعت ملف dump.cs")
        return

    msg = await update.message.reply_text("```\n> Receiving file...\n```", parse_mode="Markdown")
    file = await doc.get_file()
    content = bytes(await file.download_as_bytearray()).decode('utf-8', errors='ignore')

    await msg.edit_text("```\n> Parsing IL2CPP dump...\n```", parse_mode="Markdown")
    analyzer = get_analyzer(uid)
    trackers, tokens, classes = analyzer.analyze(content, doc.file_name or "dump.cs")

    await msg.edit_text(
        f"✅ *تم التحليل!*\n\n"
        f"📁 `{doc.file_name}`\n"
        f"🏛 Classes: `{classes}`\n"
        f"⚙️ Methods: `{len(analyzer.all_methods)}`\n"
        f"📡 Event Senders: `{trackers}`\n"
        f"🔑 Tokens: `{tokens}`",
        parse_mode="Markdown",
        reply_markup=main_keyboard()
    )


async def send_results(update: Update, context: ContextTypes.DEFAULT_TYPE, f_type=None, query=""):
    uid = update.effective_user.id
    analyzer = get_analyzer(uid)
    msg = update.message or update.callback_query.message

    if not analyzer.all_methods:
        await msg.reply_text("❌ ابعت ملف الأول.")
        return

    items = analyzer.get_filtered(f_type=f_type, query=query)
    user_results[uid] = items

    if not items:
        await msg.reply_text("❌ مفيش نتائج.")
        return

    label = query if query else (f_type or "Trackers")
    text = analyzer.format_results(items)
    header = f"*نتائج {label}* — {len(items)} نتيجة\n\n"
    full_text = header + text

    if len(full_text) > 3800:
        tmp = f"/tmp/results_{uid}.txt"
        with open(tmp, 'w', encoding='utf-8') as f:
            raw = "\n".join([
                f"[{m['mh']}] {m['cn']}.{m['mn']}({m.get('params', '')})"
                for m in items
            ])
            f.write(raw)
        await msg.reply_document(open(tmp, 'rb'), filename="results.txt",
                                  caption=f"📋 {len(items)} نتيجة")
        return

    keyboard = []
    for idx, item in enumerate(items[:5]):
        keyboard.append([
            InlineKeyboardButton(f"🎣 {item['mn'][:28]}", callback_data=f"hook_{idx}")
        ])

    await msg.reply_text(
        full_text,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard) if keyboard else None
    )


async def cmd_tokens(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    analyzer = get_analyzer(uid)
    msg = update.message or update.callback_query.message
    if not analyzer.tokens_found:
        await msg.reply_text("❌ مفيش tokens.")
        return
    lines = [f"🔑 `{t['n']}`\n   `{t['v']}`" for t in analyzer.tokens_found[:30]]
    text = "\n\n".join(lines)
    if len(text) > 3800:
        tmp = f"/tmp/tokens_{uid}.txt"
        with open(tmp, 'w') as f:
            f.write(text)
        await msg.reply_document(open(tmp, 'rb'), filename="tokens.txt")
    else:
        await msg.reply_text(text, parse_mode="Markdown")


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    analyzer = get_analyzer(uid)
    msg = update.message or update.callback_query.message
    if not analyzer.all_methods:
        await msg.reply_text("❌ ابعت ملف الأول.")
        return
    await msg.reply_text(analyzer.get_stats(), parse_mode="Markdown")


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = " ".join(context.args) if context.args else ""
    if not query:
        await update.message.reply_text("استخدام: `/search كلمة`", parse_mode="Markdown")
        return
    await send_results(update, context, query=query)


async def cmd_clear(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    user_analyzers.pop(uid, None)
    user_results.pop(uid, None)
    await update.message.reply_text("🗑 تم مسح البيانات.")


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = update.effective_user.id
    data = q.data

    filter_map = {
        "f_trackers": (None, ""),
        "f_level":    ("level", ""),
        "f_ads":      ("ads", ""),
        "f_purchase": ("purchase", ""),
        "f_network":  ("network", ""),
        "f_crypto":   ("crypto", ""),
        "f_events":   ("events", ""),
    }

    if data in filter_map:
        ft, qu = filter_map[data]
        await send_results(update, context, f_type=ft, query=qu)
    elif data == "f_tokens":
        await cmd_tokens(update, context)
    elif data == "f_stats":
        await cmd_stats(update, context)
    elif data == "f_search":
        await q.message.reply_text("🔍 ابعت: `/search كلمة`", parse_mode="Markdown")

    elif data.startswith("hook_"):
        idx = int(data.split("_")[1])
        items = user_results.get(uid, [])
        if idx >= len(items):
            return
        item = items[idx]
        keyboard = [
            [
                InlineKeyboardButton("🔬 Frida Log",   callback_data=f"gen_frida_{idx}"),
                InlineKeyboardButton("🚫 Frida Block",  callback_data=f"gen_fridablock_{idx}"),
            ],
            [
                InlineKeyboardButton("🎮 GG",       callback_data=f"gen_gg_{idx}"),
                InlineKeyboardButton("🔧 LibTool",  callback_data=f"gen_libtool_{idx}"),
            ],
        ]
        await q.message.reply_text(
            f"🎣 `{item['cn']}.{item['mn']}`\n📍 `{item['mh']}`\n\nاختار الأداة:",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("gen_"):
        parts = data.split("_")
        tool = parts[1]
        idx = int(parts[2])
        if tool == "fridablock":
            tool = "frida_block"
        items = user_results.get(uid, [])
        if idx >= len(items):
            return
        item = items[idx]
        analyzer = get_analyzer(uid)
        code = analyzer.generate_hook(item, tool)
        await q.message.reply_text(f"```javascript\n{code}\n```", parse_mode="Markdown")


def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("trackers", lambda u, c: send_results(u, c)))
    app.add_handler(CommandHandler("tokens",   cmd_tokens))
    app.add_handler(CommandHandler("level",    lambda u, c: send_results(u, c, f_type="level")))
    app.add_handler(CommandHandler("ads",      lambda u, c: send_results(u, c, f_type="ads")))
    app.add_handler(CommandHandler("purchase", lambda u, c: send_results(u, c, f_type="purchase")))
    app.add_handler(CommandHandler("network",  lambda u, c: send_results(u, c, f_type="network")))
    app.add_handler(CommandHandler("crypto",   lambda u, c: send_results(u, c, f_type="crypto")))
    app.add_handler(CommandHandler("events",   lambda u, c: send_results(u, c, f_type="events")))
    app.add_handler(CommandHandler("stats",    cmd_stats))
    app.add_handler(CommandHandler("search",   cmd_search))
    app.add_handler(CommandHandler("clear",    cmd_clear))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(CallbackQueryHandler(handle_callback))

    print("🤖 3BDEEN Bot v3 شغال!")
    app.run_polling()


if __name__ == "__main__":
    main()
