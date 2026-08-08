// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kstrtox.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kvm_para.h>
#include <linux/vm_planes.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <asm/cpu.h>
#include <asm/kvm_para.h>

#ifdef CONFIG_VM_PLANES

#define VM_PLANES_CONFIG_FILE		"config-vm-planes"
#define VM_PLANES_DEFAULT_COUNT		1

struct vm_plane_parse_state {
	phys_addr_t load_offset;
	phys_addr_t memory_size;
	unsigned int kernel_format;
	char kernel[VM_PLANE_KERNEL_NAME_MAX];
	char cmdline[VM_PLANE_CMDLINE_MAX];
};

#define VM_PLANES_UNSET_VALUE	((phys_addr_t)~0)

/*
 * Read a file from the rootfs into a newly allocated buffer.
 * Caller must kfree(*out_data) when done.
 */
static int __init vm_planes_read_file(const char *path,
				      void **out_data, loff_t *out_size)
{
	struct file *fp;
	loff_t fsize;
	void *buf;
	ssize_t rd;

	fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(fp))
		return PTR_ERR(fp);

	fsize = i_size_read(file_inode(fp));
	if (fsize <= 0) {
		fput(fp);
		return -ENODATA;
	}

	buf = kvmalloc(fsize, GFP_KERNEL);
	if (!buf) {
		fput(fp);
		return -ENOMEM;
	}

	rd = kernel_read(fp, buf, fsize, &(loff_t){0});
	fput(fp);

	if (rd != fsize) {
		kvfree(buf);
		return (rd < 0) ? (int)rd : -EIO;
	}

	*out_data = buf;
	*out_size = fsize;
	return 0;
}

/* ---- Config file parser (unchanged) ---- */

static int __init parse_plane_count_line(const char *line, size_t len,
					 unsigned int *plane_count)
{
	const char *keys[] = { "PLANE_COUNT=", "CONFIG_PLANE_COUNT=" };
	unsigned int i;

	while (len && (*line == ' ' || *line == '\t')) {
		line++;
		len--;
	}

	if (!len || *line == '#')
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		size_t key_len = strlen(keys[i]);
		size_t val_len = 0;
		char tmp[32];

		if (len <= key_len || strncmp(line, keys[i], key_len))
			continue;

		line += key_len;
		len -= key_len;
		while (val_len < len && line[val_len] != ' ' &&
		       line[val_len] != '\t' && line[val_len] != '#')
			val_len++;

		if (!val_len || val_len >= sizeof(tmp))
			return -EINVAL;

		memcpy(tmp, line, val_len);
		tmp[val_len] = '\0';

		if (kstrtouint(tmp, 0, plane_count))
			return -EINVAL;
		if (!*plane_count)
			return -EINVAL;

		return 0;
	}

	return -ENOENT;
}

static int __init parse_plane_count_kconfig(const char *buf, size_t len,
					    unsigned int *plane_count)
{
	const char *p = buf;
	const char *end = buf + len;

	while (p < end) {
		const char *eol = memchr(p, '\n', end - p);
		size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
		int ret = parse_plane_count_line(p, line_len, plane_count);

		if (!ret)
			return 0;

		p += line_len;
		if (p < end && *p == '\n')
			p++;
	}

	return -ENOENT;
}

static int __init parse_plane_cfg_line(const char *line, size_t len,
				       unsigned int plane_count,
				       struct vm_plane_config *plane_cfg,
				       struct vm_plane_parse_state *state)
{
	char tmp[VM_PLANE_CMDLINE_MAX + 64];
	char *p, *key, *val;
	unsigned int plane_id;
	u64 parsed_u64;
	phys_addr_t parsed;

	if (len >= sizeof(tmp))
		return -E2BIG;

	memcpy(tmp, line, len);
	tmp[len] = '\0';

	p = strim(tmp);
	if (!*p || *p == '#')
		return -ENOENT;

	val = strchr(p, '#');
	if (val)
		*val = '\0';
	p = strim(p);
	if (!*p)
		return -ENOENT;

	if (!strncmp(p, "CONFIG_", 7))
		p += 7;

	if (strncmp(p, "PLANE_", 6))
		return -ENOENT;
	p += 6;

	key = strchr(p, '_');
	if (!key)
		return -ENOENT;
	*key++ = '\0';

	if (kstrtouint(p, 10, &plane_id) || plane_id >= plane_count)
		return -EINVAL;

	val = strchr(key, '=');
	if (!val)
		return -EINVAL;
	*val++ = '\0';

	key = strim(key);
	val = strim(val);
	if (!*val)
		return -EINVAL;

	if (!strcmp(key, "KERNEL")) {
		size_t val_len = strlen(val);

		if (val[0] == '"') {
			if (val_len < 2 || val[val_len - 1] != '"')
				return -EINVAL;
			val[val_len - 1] = '\0';
			val++;
			val = strim(val);
		}

		if (!*val)
			return -EINVAL;

		if (strscpy(plane_cfg[plane_id].kernel, val,
			    sizeof(plane_cfg[plane_id].kernel)) < 0)
			return -EINVAL;

		strscpy(state[plane_id].kernel, val,
			sizeof(state[plane_id].kernel));
		return 0;
	}

	if (!strcmp(key, "KERNEL_FORMAT")) {
		unsigned int fmt;

		if (!strcasecmp(val, "raw"))
			fmt = VM_PLANE_KFMT_RAW;
		else if (!strcasecmp(val, "bzimage"))
			fmt = VM_PLANE_KFMT_BZIMAGE;
		else if (!strcasecmp(val, "elf"))
			fmt = VM_PLANE_KFMT_ELF;
		else
			return -EINVAL;

		plane_cfg[plane_id].kernel_format = fmt;
		state[plane_id].kernel_format = fmt;
		return 0;
	}

	if (!strcmp(key, "CMDLINE")) {
		size_t val_len = strlen(val);

		if (val_len >= 2 && val[0] == '"') {
			if (val[val_len - 1] != '"')
				return -EINVAL;
			val[val_len - 1] = '\0';
			val++;
		}

		if (strscpy(plane_cfg[plane_id].cmdline, val,
			    sizeof(plane_cfg[plane_id].cmdline)) < 0)
			return -E2BIG;

		strscpy(state[plane_id].cmdline, val,
			sizeof(state[plane_id].cmdline));
		return 0;
	}

	if (kstrtou64(val, 0, &parsed_u64))
		return -EINVAL;

	if (parsed_u64 > (u64)VM_PLANES_UNSET_VALUE)
		return -ERANGE;

	parsed = (phys_addr_t)parsed_u64;

	if (!strcmp(key, "LOAD_OFFSET")) {
		plane_cfg[plane_id].load_offset = parsed;
		state[plane_id].load_offset = parsed;
		return 0;
	}

	if (!strcmp(key, "MEMORY_SIZE")) {
		plane_cfg[plane_id].memory_size = parsed;
		state[plane_id].memory_size = parsed;
		return 0;
	}

	return -ENOENT;
}

static int __init parse_vm_planes_kconfig(const char *buf, size_t len,
				  unsigned int *plane_count,
				  struct vm_plane_config **plane_cfg)
{
	const char *p = buf;
	const char *end = buf + len;
	struct vm_plane_parse_state *state;
	unsigned int i;
	int ret;

	ret = parse_plane_count_kconfig(buf, len, plane_count);
	if (ret)
		return ret;

	if (*plane_count > UINT_MAX / sizeof(**plane_cfg))
		return -E2BIG;

	*plane_cfg = kzalloc(*plane_count * sizeof(**plane_cfg), GFP_KERNEL);
	if (!*plane_cfg)
		return -ENOMEM;

	state = kzalloc(*plane_count * sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	for (i = 0; i < *plane_count; i++) {
		state[i].load_offset = VM_PLANES_UNSET_VALUE;
		state[i].memory_size = VM_PLANES_UNSET_VALUE;
		state[i].kernel[0] = '\0';
		state[i].cmdline[0] = '\0';
	}

	while (p < end) {
		const char *eol = memchr(p, '\n', end - p);
		size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);

		ret = parse_plane_cfg_line(p, line_len, *plane_count,
					   *plane_cfg, state);
		if (ret && ret != -ENOENT)
			return ret;

		p += line_len;
		if (p < end && *p == '\n')
			p++;
	}

	for (i = 1; i < *plane_count; i++) {
		if (state[i].load_offset == VM_PLANES_UNSET_VALUE ||
		    state[i].memory_size == VM_PLANES_UNSET_VALUE ||
		    !state[i].kernel[0])
			return -EINVAL;
	}

	kfree(state);
	return 0;
}

/* ---- Config loading via VFS ---- */

static int __init vm_planes_get_cfg(unsigned int *plane_count,
				    struct vm_plane_config **plane_cfg)
{
	void *buf;
	loff_t size;
	int ret;

	ret = vm_planes_read_file("/" VM_PLANES_CONFIG_FILE, &buf, &size);
	if (ret) {
		pr_err("vm_planes: cannot read /%s: %d\n",
		       VM_PLANES_CONFIG_FILE, ret);
		return ret;
	}

	ret = parse_vm_planes_kconfig(buf, (size_t)size, plane_count, plane_cfg);
	kvfree(buf);
	return ret;
}

/* ---- Kernel loading ---- */

static int __init copy_to_early_mem(phys_addr_t dest, const void *src,
				    unsigned long size)
{
	void *p;

	if (!size)
		return 0;
	p = memremap(dest, size, MEMREMAP_WB);
	if (!p)
		return -ENOMEM;
	memcpy(p, src, size);
	memunmap(p);
	return 0;
}

static int __init zero_early_mem(phys_addr_t dest, unsigned long size)
{
	void *p;

	if (!size)
		return 0;
	p = memremap(dest, size, MEMREMAP_WB);
	if (!p)
		return -ENOMEM;
	memset(p, 0, size);
	memunmap(p);
	return 0;
}

static int __init load_plane_kernel_elf(const u8 *data, u32 size,
					struct vm_plane_config *cfg)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Phdr *phdr;
	unsigned int i;
	int ret;

	if (size < sizeof(*ehdr)) {
		pr_err("vm_planes: ELF image too small (%u bytes)\n", size);
		return -EINVAL;
	}

	ehdr = (const Elf64_Ehdr *)data;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
		pr_err("vm_planes: not a valid ELF image\n");
		return -EINVAL;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_type != ET_EXEC ||
	    ehdr->e_machine != EM_X86_64) {
		pr_err("vm_planes: unsupported ELF format (need x86_64 ET_EXEC LE)\n");
		return -EINVAL;
	}

	if (!ehdr->e_phnum || ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
		pr_err("vm_planes: invalid ELF program headers\n");
		return -EINVAL;
	}

	if (ehdr->e_phoff + (u64)ehdr->e_phnum * sizeof(Elf64_Phdr) > size) {
		pr_err("vm_planes: ELF program headers extend beyond file\n");
		return -EINVAL;
	}

	phdr = (const Elf64_Phdr *)(data + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		phys_addr_t dest;
		u64 bss_size;

		if (phdr->p_type != PT_LOAD)
			continue;

		if (!phdr->p_memsz)
			continue;

		/*
		 * Bias the ELF physical address by load_offset so that the
		 * kernel's link-time p_paddr values are treated as offsets
		 * within the plane's memory region.
		 */
		dest = cfg->load_offset + phdr->p_paddr;

		if (dest < cfg->load_offset ||
		    dest + phdr->p_memsz > cfg->load_offset + cfg->memory_size) {
			pr_err("vm_planes: ELF PT_LOAD at 0x%llx+0x%llx outside plane [0x%llx..0x%llx]\n",
			       (unsigned long long)dest,
			       (unsigned long long)phdr->p_memsz,
			       (unsigned long long)cfg->load_offset,
			       (unsigned long long)(cfg->load_offset + cfg->memory_size));
			return -EINVAL;
		}

		if (phdr->p_offset + phdr->p_filesz > size) {
			pr_err("vm_planes: ELF PT_LOAD file data beyond image\n");
			return -EINVAL;
		}

		if (phdr->p_filesz) {
			ret = copy_to_early_mem(dest, data + phdr->p_offset,
						phdr->p_filesz);
			if (ret)
				return ret;
		}

		bss_size = phdr->p_memsz - phdr->p_filesz;
		if (bss_size) {
			ret = zero_early_mem(dest + phdr->p_filesz, bss_size);
			if (ret)
				return ret;
		}

		/*
		 * Compute the physical entry point: if e_entry falls within
		 * this segment's virtual range, convert vaddr→paddr and bias.
		 * Also handle kernels where e_entry is already a physical
		 * address by checking the p_paddr range as a fallback.
		 */
		if (ehdr->e_entry >= phdr->p_vaddr &&
		    ehdr->e_entry < phdr->p_vaddr + phdr->p_memsz)
			cfg->entry_point = cfg->load_offset +
				phdr->p_paddr + (ehdr->e_entry - phdr->p_vaddr);
		else if (ehdr->e_entry >= phdr->p_paddr &&
			 ehdr->e_entry < phdr->p_paddr + phdr->p_memsz)
			cfg->entry_point = cfg->load_offset + ehdr->e_entry;

		pr_info("vm_planes: ELF PT_LOAD: paddr=0x%llx filesz=0x%llx memsz=0x%llx\n",
			(unsigned long long)dest,
			(unsigned long long)phdr->p_filesz,
			(unsigned long long)phdr->p_memsz);
	}

	if (!cfg->entry_point) {
		pr_err("vm_planes: ELF entry point 0x%llx not in any PT_LOAD segment\n",
		       (unsigned long long)ehdr->e_entry);
		return -EINVAL;
	}
	pr_info("vm_planes: ELF entry point: 0x%llx (virt 0x%llx)\n",
		(unsigned long long)cfg->entry_point,
		(unsigned long long)ehdr->e_entry);

	return 0;
}

static int __init load_plane_kernel_raw(const u8 *data, u32 size,
					struct vm_plane_config *cfg)
{
	if (size > cfg->memory_size) {
		pr_err("vm_planes: raw kernel image (%u bytes) exceeds plane memory (%llu bytes)\n",
		       size, (unsigned long long)cfg->memory_size);
		return -ENOMEM;
	}

	cfg->entry_point = cfg->load_offset;
	return copy_to_early_mem(cfg->load_offset, data, size);
}

int __init load_vm_plane_kernels(unsigned int plane_count,
				 struct vm_plane_config *plane_cfg)
{
	unsigned int i;
	int err = 0;

	for (i = 1; i < plane_count; i++) {
		void *data;
		loff_t fsize;
		int ret;

		ret = vm_planes_read_file(plane_cfg[i].kernel, &data, &fsize);
		if (ret) {
			pr_err("vm_planes: plane %u: kernel '%s' not found: %d\n",
			       i, plane_cfg[i].kernel, ret);
			err = ret;
			continue;
		}

		switch (plane_cfg[i].kernel_format) {
		case VM_PLANE_KFMT_RAW:
			ret = load_plane_kernel_raw(data, (u32)fsize,
						    &plane_cfg[i]);
			break;
		case VM_PLANE_KFMT_ELF:
			ret = load_plane_kernel_elf(data, (u32)fsize,
						    &plane_cfg[i]);
			break;
		case VM_PLANE_KFMT_BZIMAGE:
			pr_err("vm_planes: plane %u: bzImage format not yet supported\n",
			       i);
			err = -ENOSYS;
			kvfree(data);
			continue;
		default:
			pr_err("vm_planes: plane %u: unknown kernel format %u\n",
			       i, plane_cfg[i].kernel_format);
			err = -EINVAL;
			kvfree(data);
			continue;
		}

		if (ret) {
			pr_err("vm_planes: plane %u: failed to load kernel: %d\n",
			       i, ret);
			err = ret;
		} else {
			pr_info("vm_planes: plane %u: loaded '%s' (%lld bytes) at 0x%llx\n",
				i, plane_cfg[i].kernel, fsize,
				(unsigned long long)plane_cfg[i].load_offset);
		}

		kvfree(data);
	}

	return err;
}

/* ---- Activation ---- */

int __init __weak alloc_vm_planes(unsigned int plane_count,
				   struct vm_plane_config *plane_cfg) { return -ENOSYS; }

int __init __weak activate_vm_planes(unsigned int plane_count,
				      struct vm_plane_config *plane_cfg) { return -ENOSYS; }

/*
 * Set up VM planes during boot.
 *
 * Invoked from the VBS enable path at late_initcall: after device drivers
 * have initialised (so the rootfs is populated and the plane config and
 * kernels can be read) and before userspace starts, so the secure plane
 * vcpu exists by the time the first VTL call is issued.
 */
int __init vm_planes_bootstrap(void)
{
	unsigned int plane_count = VM_PLANES_DEFAULT_COUNT;
	struct vm_plane_config *plane_cfg;
	int ret;

	/* Ensure any asynchronous initramfs unpacking has completed. */
	wait_for_initramfs();

	if (!kvm_para_available()) {
		pr_info("vm_planes: KVM paravirt unavailable, skipping plane setup\n");
		return -ENODEV;
	}

	ret = vm_planes_get_cfg(&plane_count, &plane_cfg);
	if (ret) {
		pr_warn("vm_planes: failed to parse %s: %d\n",
			VM_PLANES_CONFIG_FILE, ret);
		return ret;
	}

	pr_info("vm_planes: enabling %u planes (ids 0..%u)\n",
		plane_count, plane_count - 1);

	ret = alloc_vm_planes(plane_count, plane_cfg);
	if (ret) {
		pr_err("vm_planes: failed to allocate planes: %d\n", ret);
		return ret;
	}

	ret = load_vm_plane_kernels(plane_count, plane_cfg);
	if (ret) {
		pr_err("vm_planes: failed to load plane kernels: %d\n", ret);
		return ret;
	}

	ret = activate_vm_planes(plane_count, plane_cfg);
	if (ret)
		pr_err("vm_planes: failed to activate planes: %d\n", ret);

	return ret;
}

#endif /* CONFIG_VM_PLANES */
