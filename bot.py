import discord
from discord.ext import commands
from discord import app_commands
import asyncio

# ── Bot Setup ─────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.members        = True
intents.message_content = True
intents.guilds         = True
intents.moderation     = True

bot = commands.Bot(command_prefix="!", intents=intents)

welcome_channels: set[int] = set()

SCRIPT_CHANNEL_ID = 1438819451486081034
KEY_CHANNEL_ID    = 1439944842770649238
ADMIN_ROLE_ID     = 1186686799385473147
OWNER_ID          = 1079339256666914916

SCRIPT_LOADER = 'loadstring(game:HttpGet("https://raw.githubusercontent.com/HalisBestFr/Nova/refs/heads/main/Nova%20Hub%20Loaders"))()'

# Roles that are considered "admin/staff" — expand this list if needed
PROTECTED_ROLE_IDS: set[int] = {ADMIN_ROLE_ID}

# ── Helpers ───────────────────────────────────────────────────────────────────
def is_owner(user: discord.User | discord.Member) -> bool:
    return user.id == OWNER_ID

def is_admin(member: discord.Member) -> bool:
    return (
        member.guild_permissions.administrator
        or any(r.id == ADMIN_ROLE_ID for r in member.roles)
    )

def role_is_dangerous(role: discord.Role) -> bool:
    """Returns True if a role grants kick, ban, or manage_guild (bot add) permissions."""
    critical_perms = [
        "kick_members",   # Üyeleri At
        "ban_members",    # Üyeleri Engelle
        "manage_guild",   # Sunucuya Bot Ekleme
    ]
    return any(getattr(role.permissions, perm, False) for perm in critical_perms)

# ── Get or Create Log Channel ─────────────────────────────────────────────────
async def get_log_channel(guild: discord.Guild) -> discord.TextChannel | None:
    existing = discord.utils.get(guild.text_channels, name="nova-system-log")
    if existing:
        return existing

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True),
    }
    admin_role = guild.get_role(ADMIN_ROLE_ID)
    if admin_role:
        overwrites[admin_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True)
    for role in guild.roles:
        if role.permissions.administrator:
            overwrites[role] = discord.PermissionOverwrite(view_channel=True, send_messages=True)

    channel = await guild.create_text_channel(
        name="nova-system-log",
        overwrites=overwrites,
        topic="Nova Hub — System Logs | Security & Moderation Records"
    )
    return channel

# ── Strip all roles from a member (except @everyone) ─────────────────────────
async def strip_all_roles(member: discord.Member) -> list[discord.Role]:
    removable = [r for r in member.roles if r != member.guild.default_role and r < member.guild.me.top_role]
    if removable:
        await member.remove_roles(*removable, reason="🔒 Nova Security — Automatic role strip")
    return removable

# ── on_ready ──────────────────────────────────────────────────────────────────
@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"✅  Logged in as {bot.user}!")

# ══════════════════════════════════════════════════════════════════════════════
#  🛡️  SECURITY — Unauthorized role assignment detection
# ══════════════════════════════════════════════════════════════════════════════
@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    # Check if any new dangerous roles were added
    new_roles = set(after.roles) - set(before.roles)
    if not new_roles:
        return

    dangerous_new = [r for r in new_roles if role_is_dangerous(r)]
    if not dangerous_new:
        return

    guild = after.guild

    # Find who gave the role via audit log
    assigner: discord.Member | None = None
    await asyncio.sleep(1)  # small delay so audit log is populated
    try:
        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.member_role_update):
            if entry.target.id == after.id:
                assigner = entry.user
                break
    except discord.Forbidden:
        pass

    # Don't punish the server owner or our own bot
    if assigner and (assigner.id == guild.owner_id or assigner.id == bot.user.id):
        return
    if after.id == guild.owner_id or after.id == bot.user.id:
        return

    # Trigger if the role being given contains any of the 3 critical permissions
    # Anyone who gives such a role gets punished — no admin check needed
    if not assigner:
        return  # Can't determine who gave the role, skip

    # Strip roles from the RECEIVER
    removed_from_receiver = await strip_all_roles(after)

    # Strip roles from the ASSIGNER (if found and not owner/bot)
    removed_from_assigner: list[discord.Role] = []
    if assigner and assigner.id != guild.owner_id and assigner.id != bot.user.id:
        try:
            assigner_member = guild.get_member(assigner.id)
            if assigner_member:
                removed_from_assigner = await strip_all_roles(assigner_member)
        except Exception:
            pass

    # Log the incident
    log_channel = await get_log_channel(guild)
    if log_channel:
        embed = discord.Embed(
            title="🛡️  Nova Security — Unauthorized Role Assignment",
            description=(
                "A dangerous role was given without authorization.\n"
                "**Both parties have had their roles removed.**"
            ),
            color=0xFF0000
        )
        embed.add_field(
            name="🎯 Receiver",
            value=f"{after.mention} (`{after.id}`)",
            inline=False
        )
        embed.add_field(
            name="Roles Removed from Receiver",
            value=", ".join(r.mention for r in removed_from_receiver) if removed_from_receiver else "None",
            inline=False
        )
        embed.add_field(
            name="🚨 Assigner",
            value=f"{assigner.mention} (`{assigner.id}`)" if assigner else "Unknown",
            inline=False
        )
        embed.add_field(
            name="Roles Removed from Assigner",
            value=", ".join(r.mention for r in removed_from_assigner) if removed_from_assigner else "None",
            inline=False
        )
        embed.add_field(
            name="Dangerous Roles That Were Given",
            value=", ".join(r.mention for r in dangerous_new),
            inline=False
        )
        embed.set_footer(text="ByHalis • Nova Security System")
        await log_channel.send(embed=embed)

# ══════════════════════════════════════════════════════════════════════════════
#  🛡️  SECURITY — Unauthorized bot addition detection
# ══════════════════════════════════════════════════════════════════════════════
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild

    # ── Bot detection ─────────────────────────────────────────────────────────
    if member.bot and member.id != bot.user.id:
        # Find who added the bot via audit log
        adder: discord.Member | None = None
        await asyncio.sleep(1)
        try:
            async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    adder = entry.user
                    break
        except discord.Forbidden:
            pass

        # Allow if the server owner added it
        if adder and adder.id == guild.owner_id:
            return

        # Ban the unauthorized bot
        try:
            await member.ban(reason="🔒 Nova Security — Unauthorized bot addition")
        except discord.Forbidden:
            pass

        # Strip roles from whoever added it
        removed_from_adder: list[discord.Role] = []
        if adder and adder.id != guild.owner_id and adder.id != bot.user.id:
            try:
                adder_member = guild.get_member(adder.id)
                if adder_member:
                    removed_from_adder = await strip_all_roles(adder_member)
            except Exception:
                pass

        # Log
        log_channel = await get_log_channel(guild)
        if log_channel:
            embed = discord.Embed(
                title="🤖  Nova Security — Unauthorized Bot Added",
                description=(
                    "An unauthorized bot was added to the server.\n"
                    "**The bot has been banned and the adder's roles have been removed.**"
                ),
                color=0xFF4500
            )
            embed.add_field(name="🚫 Banned Bot", value=f"{member} (`{member.id}`)", inline=False)
            embed.add_field(
                name="🚨 Added By",
                value=f"{adder.mention} (`{adder.id}`)" if adder else "Unknown",
                inline=False
            )
            embed.add_field(
                name="Roles Removed from Adder",
                value=", ".join(r.mention for r in removed_from_adder) if removed_from_adder else "None",
                inline=False
            )
            embed.set_footer(text="ByHalis • Nova Security System")
            await log_channel.send(embed=embed)
        return

    # ── Normal member welcome ──────────────────────────────────────────────────
    for channel_id in welcome_channels:
        channel = guild.get_channel(channel_id)
        if channel:
            member_count = guild.member_count
            embed = discord.Embed(
                title="🌟  Welcome to Nova Hub!",
                description=(
                    f"Hey {member.mention}! 👋\n\n"
                    f"You are our **#{member_count}** member — glad to have you here! 🎉\n\n"
                    "**Nova Hub** offers premium, high-quality scripts for a wide variety of games. 🚀\n\n"
                    "━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"📜 **Script:** <#{SCRIPT_CHANNEL_ID}>\n"
                    f"🔑 **Key:** <#{KEY_CHANNEL_ID}>\n"
                    "━━━━━━━━━━━━━━━━━━━━━━"
                ),
                color=0x5865F2
            )
            embed.set_footer(text="ByHalis")
            embed.set_thumbnail(url=member.display_avatar.url)
            await channel.send(embed=embed)

# ── /welcome ──────────────────────────────────────────────────────────────────
@bot.tree.command(name="welcome", description="Start the welcome system in this channel.")
async def welcome(interaction: discord.Interaction):
    if not is_owner(interaction.user):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
        return
    welcome_channels.add(interaction.channel_id)
    embed = discord.Embed(
        title="✅  Welcome System Activated",
        description=(
            f"The welcome system has been successfully started in {interaction.channel.mention}!\n\n"
            "Every new member who joins the server will be greeted here automatically."
        ),
        color=0x57F287
    )
    embed.set_footer(text="ByHalis")
    await interaction.response.send_message(embed=embed)

# ── Copy Button View ──────────────────────────────────────────────────────────
class CopyScriptView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="📋  Copy Script", style=discord.ButtonStyle.secondary, custom_id="copy_script")
    async def copy_script(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            f"✅ **Script copied!** Paste it into your executor:\n```lua\n{SCRIPT_LOADER}\n```",
            ephemeral=True
        )

# ── Ticket Views ──────────────────────────────────────────────────────────────
class CreateTicketView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="📩  Create Ticket", style=discord.ButtonStyle.primary, custom_id="create_ticket")
    async def create_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild  = interaction.guild
        member = interaction.user
        safe_name = member.display_name.lower().replace(" ", "-")
        existing  = discord.utils.get(guild.text_channels, name=f"ticket-{safe_name}")
        if existing:
            await interaction.response.send_message(f"❌ You already have an open ticket: {existing.mention}", ephemeral=True)
            return

        overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False),
            member: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
        }
        admin_role = guild.get_role(ADMIN_ROLE_ID)
        if admin_role:
            overwrites[admin_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)

        ticket_channel = await guild.create_text_channel(
            name=f"ticket-{member.display_name}",
            overwrites=overwrites,
            category=interaction.channel.category,
            topic=f"Support ticket opened by {member}"
        )

        ticket_embed = discord.Embed(
            title="🎫  Nova Hub — Support Center",
            description=(
                f"Welcome {member.mention}! 👋\n\n"
                "Hope you're having a great day! ☀️\n\n"
                "You have successfully opened a support ticket.\n"
                "Please **briefly explain** your request or issue "
                "and wait for one of our staff members to assist you.\n\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "⏳ A staff member will be with you shortly.\n"
                "━━━━━━━━━━━━━━━━━━━━━━"
            ),
            color=0x5865F2
        )
        ticket_embed.set_footer(text="ByHalis")
        await ticket_channel.send(content=member.mention, embed=ticket_embed, view=CloseTicketView())
        await interaction.response.send_message(f"✅ Your ticket has been created: {ticket_channel.mention}", ephemeral=True)


class CloseTicketView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="🔒  Close Ticket", style=discord.ButtonStyle.danger, custom_id="close_ticket")
    async def close_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not is_admin(interaction.user):
            await interaction.response.send_message("❌ Only administrators can close tickets.", ephemeral=True)
            return
        embed = discord.Embed(
            title="🔒  Ticket Closed",
            description="This ticket has been **closed** by a staff member.\n\n⏳ This channel will be **automatically deleted in 2 minutes**.",
            color=0xED4245
        )
        embed.set_footer(text="ByHalis")
        await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=False, view_channel=False)
        await interaction.response.send_message(embed=embed)
        await asyncio.sleep(120)
        await interaction.channel.delete()

# ── /ticket ───────────────────────────────────────────────────────────────────
@bot.tree.command(name="ticket", description="Send the support ticket panel in this channel.")
async def ticket(interaction: discord.Interaction):
    if not is_owner(interaction.user):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
        return
    embed = discord.Embed(
        title="🎫  Nova Hub — Support System",
        description=(
            "If you have any **private questions**, want to purchase a **Paid Script**, "
            "or need help with a specific topic —\n\n"
            "Click the **Create Ticket** button below and our staff will assist you as soon as possible! 💬\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "📌 Please be patient after opening your ticket.\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        ),
        color=0x5865F2
    )
    embed.set_footer(text="ByHalis")
    await interaction.response.send_message(embed=embed, view=CreateTicketView())

# ── /script ───────────────────────────────────────────────────────────────────
@bot.tree.command(name="script", description="Get the Nova Hub script loader.")
async def script(interaction: discord.Interaction):
    if not is_owner(interaction.user):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
        return
    embed = discord.Embed(
        title="📜  Nova Hub — Script Loader",
        description=(
            "Welcome to **Nova Hub**! 🌟\n\n"
            "We offer the **best open-source scripts** for a wide variety of games — "
            "crafted with quality and precision for the ultimate gaming experience.\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "**Execute the loader below in your exploit:**\n\n"
            f"```lua\n{SCRIPT_LOADER}\n```\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔑 Need a key? Head over to <#{KEY_CHANNEL_ID}>\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        ),
        color=0xFEE75C
    )
    embed.set_footer(text="ByHalis")
    await interaction.response.send_message(embed=embed, view=CopyScriptView())

# ── /key ──────────────────────────────────────────────────────────────────────
@bot.tree.command(name="key", description="Get your Nova Hub script key.")
async def key(interaction: discord.Interaction):
    if not is_owner(interaction.user):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
        return
    embed = discord.Embed(
        title="🔑  Nova Hub — Script Key",
        description=(
            f"Welcome back, **{interaction.user.display_name}**! 👋\n\n"
            "In order to use Nova Hub's professional scripts, you will need the key shown below.\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "# 🗝️  `NovaHub`\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "⚠️ **Important:** The correct key is exactly **`NovaHub`**\n"
            "— not `Nova Hub`, not `novahub`, not `NOVAHUB` — just: **`NovaHub`**\n\n"
            "Copy it exactly as shown and paste it into the key prompt.\n\n"
            f"📜 Don't have the script yet? Go to <#{SCRIPT_CHANNEL_ID}>\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        ),
        color=0x57F287
    )
    embed.set_footer(text="ByHalis")
    await interaction.response.send_message(embed=embed)

# ── /ban ──────────────────────────────────────────────────────────────────────
@bot.tree.command(name="ban", description="Ban a member from the server.")
@app_commands.describe(member="The member to ban", reason="Reason for the ban")
async def ban(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not is_owner(interaction.user):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
        return
    try:
        await member.ban(reason=reason)
        embed = discord.Embed(
            title="🔨  Member Banned",
            description=f"**{member}** has been successfully banned.\n\n📋 **Reason:** {reason}",
            color=0xED4245
        )
        embed.set_footer(text="ByHalis")
        embed.set_thumbnail(url=member.display_avatar.url)
        await interaction.response.send_message(embed=embed)

        log_channel = await get_log_channel(interaction.guild)
        if log_channel:
            log_embed = discord.Embed(title="🔨  Nova System Log — Ban", color=0xED4245)
            log_embed.add_field(name="Banned User", value=f"{member} (`{member.id}`)", inline=False)
            log_embed.add_field(name="Banned By", value=f"{interaction.user} (`{interaction.user.id}`)", inline=False)
            log_embed.add_field(name="Reason", value=reason, inline=False)
            log_embed.set_footer(text="ByHalis")
            log_embed.set_thumbnail(url=member.display_avatar.url)
            await log_channel.send(embed=log_embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I don't have permission to ban this member.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"❌ An error occurred: {e}", ephemeral=True)

# ── /kick ─────────────────────────────────────────────────────────────────────
@bot.tree.command(name="kick", description="Kick a member from the server.")
@app_commands.describe(member="The member to kick", reason="Reason for the kick")
async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not is_owner(interaction.user):
        await interaction.response.send_message("❌ You don't have permission to use this command.", ephemeral=True)
        return
    try:
        await member.kick(reason=reason)
        embed = discord.Embed(
            title="👢  Member Kicked",
            description=f"**{member}** has been successfully kicked.\n\n📋 **Reason:** {reason}",
            color=0xFFA500
        )
        embed.set_footer(text="ByHalis")
        embed.set_thumbnail(url=member.display_avatar.url)
        await interaction.response.send_message(embed=embed)

        log_channel = await get_log_channel(interaction.guild)
        if log_channel:
            log_embed = discord.Embed(title="👢  Nova System Log — Kick", color=0xFFA500)
            log_embed.add_field(name="Kicked User", value=f"{member} (`{member.id}`)", inline=False)
            log_embed.add_field(name="Kicked By", value=f"{interaction.user} (`{interaction.user.id}`)", inline=False)
            log_embed.add_field(name="Reason", value=reason, inline=False)
            log_embed.set_footer(text="ByHalis")
            log_embed.set_thumbnail(url=member.display_avatar.url)
            await log_channel.send(embed=log_embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I don't have permission to kick this member.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"❌ An error occurred: {e}", ephemeral=True)

bot.run("MTQ4MTYxNjc5MDIzMTcxNTkyMg.GxfZo4.Xdjtbl-xNcA7z54ohLx_8tOJE3z28YU-ZU8Ht4")
