/*
 * SCSI Primary Commands (SPC) parsing and emulation.
 *
 * (c) Copyright 2002-2013 Datera, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/unaligned.h>

#include <scsi/scsi_proto.h>
#include <scsi/scsi_common.h>
#include <scsi/scsi_tcq.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>

#include "target_core_internal.h"
#include "target_core_alua.h"
#include "target_core_pr.h"
#include "target_core_ua.h"
#include "target_core_xcopy.h"

static void spc_fill_alua_data(struct se_lun *lun, unsigned char *buf)
{
	struct t10_alua_tg_pt_gp *tg_pt_gp;

	/*
	 * Set SCCS for MAINTENANCE_IN + REPORT_TARGET_PORT_GROUPS.
	 */
	buf[5]	= 0x80;

	/*
	 * Set TPGS field for explicit and/or implicit ALUA access type
	 * and opteration.
	 *
	 * See spc4r17 section 6.4.2 Table 135
	 */
	spin_lock(&lun->lun_tg_pt_gp_lock);
	tg_pt_gp = lun->lun_tg_pt_gp;
	if (tg_pt_gp)
		buf[5] |= tg_pt_gp->tg_pt_gp_alua_access_type;
	spin_unlock(&lun->lun_tg_pt_gp_lock);
}

sense_reason_t
spc_emulate_inquiry_std(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_lun *lun = cmd->se_lun;
	struct se_device *dev = cmd->se_dev;
	struct se_session *sess = cmd->se_sess;

	/* Set RMB (removable media) for tape devices */
	if (dev->transport->get_device_type(dev) == TYPE_TAPE)
		buf[1] = 0x80;

	buf[2] = 0x05; /* SPC-3 */

	/*
	 * NORMACA and HISUP = 0, RESPONSE DATA FORMAT = 2
	 *
	 * SPC4 says:
	 *   A RESPONSE DATA FORMAT field set to 2h indicates that the
	 *   standard INQUIRY data is in the format defined in this
	 *   standard. Response data format values less than 2h are
	 *   obsolete. Response data format values greater than 2h are
	 *   reserved.
	 */
	buf[3] = 2;

	/*
	 * Enable SCCS and TPGS fields for Emulated ALUA
	 */
	spc_fill_alua_data(lun, buf);

	/*
	 * Set Third-Party Copy (3PC) bit to indicate support for EXTENDED_COPY
	 */
	if (dev->dev_attrib.emulate_3pc)
		buf[5] |= 0x8;
	/*
	 * Set Protection (PROTECT) bit when DIF has been enabled on the
	 * device, and the fabric supports VERIFY + PASS.  Also report
	 * PROTECT=1 if sess_prot_type has been configured to allow T10-PI
	 * to unprotected devices.
	 */
	if (sess->sup_prot_ops & (TARGET_PROT_DIN_PASS | TARGET_PROT_DOUT_PASS)) {
		if (dev->dev_attrib.pi_prot_type || cmd->se_sess->sess_prot_type)
			buf[5] |= 0x1;
	}

	buf[7] = 0x2; /* CmdQue=1 */

	/*
	 * ASCII data fields described as being left-aligned shall have any
	 * unused bytes at the end of the field (i.e., highest offset) and the
	 * unused bytes shall be filled with ASCII space characters (20h).
	 */
	memset(&buf[8], 0x20,
	       INQUIRY_VENDOR_LEN + INQUIRY_MODEL_LEN + INQUIRY_REVISION_LEN);
	memcpy(&buf[8], dev->t10_wwn.vendor,
	       strnlen(dev->t10_wwn.vendor, INQUIRY_VENDOR_LEN));
	memcpy(&buf[16], dev->t10_wwn.model,
	       strnlen(dev->t10_wwn.model, INQUIRY_MODEL_LEN));
	memcpy(&buf[32], dev->t10_wwn.revision,
	       strnlen(dev->t10_wwn.revision, INQUIRY_REVISION_LEN));
	buf[4] = 31; /* Set additional length to 31 */

	return 0;
}
EXPORT_SYMBOL(spc_emulate_inquiry_std);

/* unit serial number */
static sense_reason_t
spc_emulate_evpd_80(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;
	u16 len;

	if (dev->dev_flags & DF_EMULATED_VPD_UNIT_SERIAL) {
		len = sprintf(&buf[4], "%s", dev->t10_wwn.unit_serial);
		len++; /* Extra Byte for NULL Terminator */
		buf[3] = len;
	}
	return 0;
}

void spc_parse_naa_6h_vendor_specific(struct se_device *dev,
				      unsigned char *buf)
{
	unsigned char *p = &dev->t10_wwn.unit_serial[0];
	int cnt;
	bool next = true;

	/*
	 * Generate up to 36 bits of VENDOR SPECIFIC IDENTIFIER starting on
	 * byte 3 bit 3-0 for NAA IEEE Registered Extended DESIGNATOR field
	 * format, followed by 64 bits of VENDOR SPECIFIC IDENTIFIER EXTENSION
	 * to complete the payload.  These are based from VPD=0x80 PRODUCT SERIAL
	 * NUMBER set via vpd_unit_serial in target_core_configfs.c to ensure
	 * per device uniqeness.
	 */
	for (cnt = 0; *p && cnt < 13; p++) {
		int val = hex_to_bin(*p);

		if (val < 0)
			continue;

		if (next) {
			next = false;
			buf[cnt++] |= val;
		} else {
			next = true;
			buf[cnt] = val << 4;
		}
	}
}

/*
 * Device identification VPD, for a complete list of
 * DESIGNATOR TYPEs see spc4r17 Table 459.
 */
sense_reason_t
spc_emulate_evpd_83(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;
	struct se_lun *lun = cmd->se_lun;
	struct se_portal_group *tpg = NULL;
	struct t10_alua_lu_gp_member *lu_gp_mem;
	struct t10_alua_tg_pt_gp *tg_pt_gp;
	unsigned char *prod = &dev->t10_wwn.model[0];
	u32 prod_len;
	u32 unit_serial_len, off = 0;
	u16 len = 0, id_len;

	off = 4;

	/*
	 * NAA IEEE Registered Extended Assigned designator format, see
	 * spc4r17 section 7.7.3.6.5
	 *
	 * We depend upon a target_core_mod/ConfigFS provided
	 * /sys/kernel/config/target/core/$HBA/$DEV/wwn/vpd_unit_serial
	 * value in order to return the NAA id.
	 */
	if (!(dev->dev_flags & DF_EMULATED_VPD_UNIT_SERIAL))
		goto check_t10_vend_desc;

	/* CODE SET == Binary */
	buf[off++] = 0x1;

	/* Set ASSOCIATION == addressed logical unit: 0)b */
	buf[off] = 0x00;

	/* Identifier/Designator type == NAA identifier */
	buf[off++] |= 0x3;
	off++;

	/* Identifier/Designator length */
	buf[off++] = 0x10;

	/*
	 * Start NAA IEEE Registered Extended Identifier/Designator
	 */
	buf[off++] = (0x6 << 4);

	/*
	 * Use OpenFabrics IEEE Company ID: 00 14 05
	 */
	buf[off++] = 0x01;
	buf[off++] = 0x40;
	buf[off] = (0x5 << 4);

	/*
	 * Return ConfigFS Unit Serial Number information for
	 * VENDOR_SPECIFIC_IDENTIFIER and
	 * VENDOR_SPECIFIC_IDENTIFIER_EXTENTION
	 */
	spc_parse_naa_6h_vendor_specific(dev, &buf[off]);

	len = 20;
	off = (len + 4);

check_t10_vend_desc:
	/*
	 * T10 Vendor Identifier Page, see spc4r17 section 7.7.3.4
	 */
	id_len = 8; /* For Vendor field */
	prod_len = 4; /* For VPD Header */
	prod_len += 8; /* For Vendor field */
	prod_len += strlen(prod);
	prod_len++; /* For : */

	if (dev->dev_flags & DF_EMULATED_VPD_UNIT_SERIAL) {
		unit_serial_len = strlen(&dev->t10_wwn.unit_serial[0]);
		unit_serial_len++; /* For NULL Terminator */

		id_len += sprintf(&buf[off+12], "%s:%s", prod,
				&dev->t10_wwn.unit_serial[0]);
	}
	buf[off] = 0x2; /* ASCII */
	buf[off+1] = 0x1; /* T10 Vendor ID */
	buf[off+2] = 0x0;
	/* left align Vendor ID and pad with spaces */
	memset(&buf[off+4], 0x20, INQUIRY_VENDOR_LEN);
	memcpy(&buf[off+4], dev->t10_wwn.vendor,
	       strnlen(dev->t10_wwn.vendor, INQUIRY_VENDOR_LEN));
	/* Extra Byte for NULL Terminator */
	id_len++;
	/* Identifier Length */
	buf[off+3] = id_len;
	/* Header size for Designation descriptor */
	len += (id_len + 4);
	off += (id_len + 4);

	if (1) {
		struct t10_alua_lu_gp *lu_gp;
		u32 padding, scsi_name_len, scsi_target_len;
		u16 lu_gp_id = 0;
		u16 tg_pt_gp_id = 0;
		u16 tpgt;

		tpg = lun->lun_tpg;
		/*
		 * Relative target port identifer, see spc4r17
		 * section 7.7.3.7
		 *
		 * Get the PROTOCOL IDENTIFIER as defined by spc4r17
		 * section 7.5.1 Table 362
		 */
		buf[off] = tpg->proto_id << 4;
		buf[off++] |= 0x1; /* CODE SET == Binary */
		buf[off] = 0x80; /* Set PIV=1 */
		/* Set ASSOCIATION == target port: 01b */
		buf[off] |= 0x10;
		/* DESIGNATOR TYPE == Relative target port identifer */
		buf[off++] |= 0x4;
		off++; /* Skip over Reserved */
		buf[off++] = 4; /* DESIGNATOR LENGTH */
		/* Skip over Obsolete field in RTPI payload
		 * in Table 472 */
		off += 2;
		put_unaligned_be16(lun->lun_rtpi, &buf[off]);
		off += 2;
		len += 8; /* Header size + Designation descriptor */
		/*
		 * Target port group identifier, see spc4r17
		 * section 7.7.3.8
		 *
		 * Get the PROTOCOL IDENTIFIER as defined by spc4r17
		 * section 7.5.1 Table 362
		 */
		spin_lock(&lun->lun_tg_pt_gp_lock);
		tg_pt_gp = lun->lun_tg_pt_gp;
		if (!tg_pt_gp) {
			spin_unlock(&lun->lun_tg_pt_gp_lock);
			goto check_lu_gp;
		}
		tg_pt_gp_id = tg_pt_gp->tg_pt_gp_id;
		spin_unlock(&lun->lun_tg_pt_gp_lock);

		buf[off] = tpg->proto_id << 4;
		buf[off++] |= 0x1; /* CODE SET == Binary */
		buf[off] = 0x80; /* Set PIV=1 */
		/* Set ASSOCIATION == target port: 01b */
		buf[off] |= 0x10;
		/* DESIGNATOR TYPE == Target port group identifier */
		buf[off++] |= 0x5;
		off++; /* Skip over Reserved */
		buf[off++] = 4; /* DESIGNATOR LENGTH */
		off += 2; /* Skip over Reserved Field */
		put_unaligned_be16(tg_pt_gp_id, &buf[off]);
		off += 2;
		len += 8; /* Header size + Designation descriptor */
		/*
		 * Logical Unit Group identifier, see spc4r17
		 * section 7.7.3.8
		 */
check_lu_gp:
		lu_gp_mem = dev->dev_alua_lu_gp_mem;
		if (!lu_gp_mem)
			goto check_scsi_name;

		spin_lock(&lu_gp_mem->lu_gp_mem_lock);
		lu_gp = lu_gp_mem->lu_gp;
		if (!lu_gp) {
			spin_unlock(&lu_gp_mem->lu_gp_mem_lock);
			goto check_scsi_name;
		}
		lu_gp_id = lu_gp->lu_gp_id;
		spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

		buf[off++] |= 0x1; /* CODE SET == Binary */
		/* DESIGNATOR TYPE == Logical Unit Group identifier */
		buf[off++] |= 0x6;
		off++; /* Skip over Reserved */
		buf[off++] = 4; /* DESIGNATOR LENGTH */
		off += 2; /* Skip over Reserved Field */
		put_unaligned_be16(lu_gp_id, &buf[off]);
		off += 2;
		len += 8; /* Header size + Designation descriptor */
		/*
		 * SCSI name string designator, see spc4r17
		 * section 7.7.3.11
		 *
		 * Get the PROTOCOL IDENTIFIER as defined by spc4r17
		 * section 7.5.1 Table 362
		 */
check_scsi_name:
		buf[off] = tpg->proto_id << 4;
		buf[off++] |= 0x3; /* CODE SET == UTF-8 */
		buf[off] = 0x80; /* Set PIV=1 */
		/* Set ASSOCIATION == target port: 01b */
		buf[off] |= 0x10;
		/* DESIGNATOR TYPE == SCSI name string */
		buf[off++] |= 0x8;
		off += 2; /* Skip over Reserved and length */
		/*
		 * SCSI name string identifer containing, $FABRIC_MOD
		 * dependent information.  For LIO-Target and iSCSI
		 * Target Port, this means "<iSCSI name>,t,0x<TPGT> in
		 * UTF-8 encoding.
		 */
		tpgt = tpg->se_tpg_tfo->tpg_get_tag(tpg);
		scsi_name_len = sprintf(&buf[off], "%s,t,0x%04x",
					tpg->se_tpg_tfo->tpg_get_wwn(tpg), tpgt);
		scsi_name_len += 1 /* Include  NULL terminator */;
		/*
		 * The null-terminated, null-padded (see 4.4.2) SCSI
		 * NAME STRING field contains a UTF-8 format string.
		 * The number of bytes in the SCSI NAME STRING field
		 * (i.e., the value in the DESIGNATOR LENGTH field)
		 * shall be no larger than 256 and shall be a multiple
		 * of four.
		 */
		padding = ((-scsi_name_len) & 3);
		if (padding)
			scsi_name_len += padding;
		if (scsi_name_len > 256)
			scsi_name_len = 256;

		buf[off-1] = scsi_name_len;
		off += scsi_name_len;
		/* Header size + Designation descriptor */
		len += (scsi_name_len + 4);

		/*
		 * Target device designator
		 */
		buf[off] = tpg->proto_id << 4;
		buf[off++] |= 0x3; /* CODE SET == UTF-8 */
		buf[off] = 0x80; /* Set PIV=1 */
		/* Set ASSOCIATION == target device: 10b */
		buf[off] |= 0x20;
		/* DESIGNATOR TYPE == SCSI name string */
		buf[off++] |= 0x8;
		off += 2; /* Skip over Reserved and length */
		/*
		 * SCSI name string identifer containing, $FABRIC_MOD
		 * dependent information.  For LIO-Target and iSCSI
		 * Target Port, this means "<iSCSI name>" in
		 * UTF-8 encoding.
		 */
		scsi_target_len = sprintf(&buf[off], "%s",
					  tpg->se_tpg_tfo->tpg_get_wwn(tpg));
		scsi_target_len += 1 /* Include  NULL terminator */;
		/*
		 * The null-terminated, null-padded (see 4.4.2) SCSI
		 * NAME STRING field contains a UTF-8 format string.
		 * The number of bytes in the SCSI NAME STRING field
		 * (i.e., the value in the DESIGNATOR LENGTH field)
		 * shall be no larger than 256 and shall be a multiple
		 * of four.
		 */
		padding = ((-scsi_target_len) & 3);
		if (padding)
			scsi_target_len += padding;
		if (scsi_target_len > 256)
			scsi_target_len = 256;

		buf[off-1] = scsi_target_len;
		off += scsi_target_len;

		/* Header size + Designation descriptor */
		len += (scsi_target_len + 4);
	}
	put_unaligned_be16(len, &buf[2]); /* Page Length for VPD 0x83 */
	return 0;
}
EXPORT_SYMBOL(spc_emulate_evpd_83);

/* Extended INQUIRY Data VPD Page */
static sense_reason_t
spc_emulate_evpd_86(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;
	struct se_session *sess = cmd->se_sess;

	buf[3] = 0x3c;
	/*
	 * Set GRD_CHK + REF_CHK for TYPE1 protection, or GRD_CHK
	 * only for TYPE3 protection.
	 */
	if (sess->sup_prot_ops & (TARGET_PROT_DIN_PASS | TARGET_PROT_DOUT_PASS)) {
		if (dev->dev_attrib.pi_prot_type == TARGET_DIF_TYPE1_PROT ||
		    cmd->se_sess->sess_prot_type == TARGET_DIF_TYPE1_PROT)
			buf[4] = 0x5;
		else if (dev->dev_attrib.pi_prot_type == TARGET_DIF_TYPE3_PROT ||
			 cmd->se_sess->sess_prot_type == TARGET_DIF_TYPE3_PROT)
			buf[4] = 0x4;
	}

	/* logical unit supports type 1 and type 3 protection */
	if ((dev->transport->get_device_type(dev) == TYPE_DISK) &&
	    (sess->sup_prot_ops & (TARGET_PROT_DIN_PASS | TARGET_PROT_DOUT_PASS)) &&
	    (dev->dev_attrib.pi_prot_type || cmd->se_sess->sess_prot_type)) {
		buf[4] |= (0x3 << 3);
	}

	/* Set HEADSUP, ORDSUP, SIMPSUP */
	buf[5] = 0x07;

	/* If WriteCache emulation is enabled, set V_SUP */
	if (target_check_wce(dev))
		buf[6] = 0x01;
	/* If an LBA map is present set R_SUP */
	spin_lock(&cmd->se_dev->t10_alua.lba_map_lock);
	if (!list_empty(&dev->t10_alua.lba_map_list))
		buf[8] = 0x10;
	spin_unlock(&cmd->se_dev->t10_alua.lba_map_lock);
	return 0;
}

/* Block Limits VPD page */
static sense_reason_t
spc_emulate_evpd_b0(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;
	u32 mtl = 0;
	int have_tp = 0, opt, min;

	/*
	 * Following spc3r22 section 6.5.3 Block Limits VPD page, when
	 * emulate_tpu=1 or emulate_tpws=1 we will be expect a
	 * different page length for Thin Provisioning.
	 */
	if (dev->dev_attrib.emulate_tpu || dev->dev_attrib.emulate_tpws)
		have_tp = 1;

	buf[0] = dev->transport->get_device_type(dev);
	buf[3] = have_tp ? 0x3c : 0x10;

	/* Set WSNZ to 1 */
	buf[4] = 0x01;
	/*
	 * Set MAXIMUM COMPARE AND WRITE LENGTH
	 */
	if (dev->dev_attrib.emulate_caw)
		buf[5] = 0x01;

	/*
	 * Set OPTIMAL TRANSFER LENGTH GRANULARITY
	 */
	if (dev->transport->get_io_min && (min = dev->transport->get_io_min(dev)))
		put_unaligned_be16(min / dev->dev_attrib.block_size, &buf[6]);
	else
		put_unaligned_be16(1, &buf[6]);

	/*
	 * Set MAXIMUM TRANSFER LENGTH
	 *
	 * XXX: Currently assumes single PAGE_SIZE per scatterlist for fabrics
	 * enforcing maximum HW scatter-gather-list entry limit
	 */
	if (cmd->se_tfo->max_data_sg_nents) {
		mtl = (cmd->se_tfo->max_data_sg_nents * PAGE_SIZE) /
		       dev->dev_attrib.block_size;
	}
	put_unaligned_be32(min_not_zero(mtl, dev->dev_attrib.hw_max_sectors), &buf[8]);

	/*
	 * Set OPTIMAL TRANSFER LENGTH
	 */
	if (dev->transport->get_io_opt && (opt = dev->transport->get_io_opt(dev)))
		put_unaligned_be32(opt / dev->dev_attrib.block_size, &buf[12]);
	else
		put_unaligned_be32(dev->dev_attrib.optimal_sectors, &buf[12]);

	/*
	 * Exit now if we don't support TP.
	 */
	if (!have_tp)
		goto max_write_same;

	/*
	 * Set MAXIMUM UNMAP LBA COUNT
	 */
	put_unaligned_be32(dev->dev_attrib.max_unmap_lba_count, &buf[20]);

	/*
	 * Set MAXIMUM UNMAP BLOCK DESCRIPTOR COUNT
	 */
	put_unaligned_be32(dev->dev_attrib.max_unmap_block_desc_count,
			   &buf[24]);

	/*
	 * Set OPTIMAL UNMAP GRANULARITY
	 */
	put_unaligned_be32(dev->dev_attrib.unmap_granularity, &buf[28]);

	/*
	 * UNMAP GRANULARITY ALIGNMENT
	 */
	put_unaligned_be32(dev->dev_attrib.unmap_granularity_alignment,
			   &buf[32]);
	if (dev->dev_attrib.unmap_granularity_alignment != 0)
		buf[32] |= 0x80; /* Set the UGAVALID bit */

	/*
	 * MAXIMUM WRITE SAME LENGTH
	 */
max_write_same:
	put_unaligned_be64(dev->dev_attrib.max_write_same_len, &buf[36]);

	return 0;
}

/* Block Device Characteristics VPD page */
static sense_reason_t
spc_emulate_evpd_b1(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;

	buf[0] = dev->transport->get_device_type(dev);
	buf[3] = 0x3c;
	buf[5] = dev->dev_attrib.is_nonrot ? 1 : 0;

	return 0;
}

/* Thin Provisioning VPD */
static sense_reason_t
spc_emulate_evpd_b2(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;

	/*
	 * From spc3r22 section 6.5.4 Thin Provisioning VPD page:
	 *
	 * The PAGE LENGTH field is defined in SPC-4. If the DP bit is set to
	 * zero, then the page length shall be set to 0004h.  If the DP bit
	 * is set to one, then the page length shall be set to the value
	 * defined in table 162.
	 */
	buf[0] = dev->transport->get_device_type(dev);

	/*
	 * Set Hardcoded length mentioned above for DP=0
	 */
	put_unaligned_be16(0x0004, &buf[2]);

	/*
	 * The THRESHOLD EXPONENT field indicates the threshold set size in
	 * LBAs as a power of 2 (i.e., the threshold set size is equal to
	 * 2(threshold exponent)).
	 *
	 * Note that this is currently set to 0x00 as mkp says it will be
	 * changing again.  We can enable this once it has settled in T10
	 * and is actually used by Linux/SCSI ML code.
	 */
	buf[4] = 0x00;

	/*
	 * A TPU bit set to one indicates that the device server supports
	 * the UNMAP command (see 5.25). A TPU bit set to zero indicates
	 * that the device server does not support the UNMAP command.
	 */
	if (dev->dev_attrib.emulate_tpu != 0)
		buf[5] = 0x80;

	/*
	 * A TPWS bit set to one indicates that the device server supports
	 * the use of the WRITE SAME (16) command (see 5.42) to unmap LBAs.
	 * A TPWS bit set to zero indicates that the device server does not
	 * support the use of the WRITE SAME (16) command to unmap LBAs.
	 */
	if (dev->dev_attrib.emulate_tpws != 0)
		buf[5] |= 0x40 | 0x20;

	/*
	 * The unmap_zeroes_data set means that the underlying device supports
	 * REQ_OP_DISCARD and has the discard_zeroes_data bit set. This
	 * satisfies the SBC requirements for LBPRZ, meaning that a subsequent
	 * read will return zeroes after an UNMAP or WRITE SAME (16) to an LBA
	 * See sbc4r36 6.6.4.
	 */
	if (((dev->dev_attrib.emulate_tpu != 0) ||
	     (dev->dev_attrib.emulate_tpws != 0)) &&
	     (dev->dev_attrib.unmap_zeroes_data != 0))
		buf[5] |= 0x04;

	return 0;
}

/* Referrals VPD page */
static sense_reason_t
spc_emulate_evpd_b3(struct se_cmd *cmd, unsigned char *buf)
{
	struct se_device *dev = cmd->se_dev;

	buf[0] = dev->transport->get_device_type(dev);
	buf[3] = 0x0c;
	put_unaligned_be32(dev->t10_alua.lba_map_segment_size, &buf[8]);
	put_unaligned_be32(dev->t10_alua.lba_map_segment_multiplier, &buf[12]);

	return 0;
}

static sense_reason_t
spc_emulate_evpd_00(struct se_cmd *cmd, unsigned char *buf);

static struct {
	uint8_t		page;
	sense_reason_t	(*emulate)(struct se_cmd *, unsigned char *);
} evpd_handlers[] = {
	{ .page = 0x00, .emulate = spc_emulate_evpd_00 },
	{ .page = 0x80, .emulate = spc_emulate_evpd_80 },
	{ .page = 0x83, .emulate = spc_emulate_evpd_83 },
	{ .page = 0x86, .emulate = spc_emulate_evpd_86 },
	{ .page = 0xb0, .emulate = spc_emulate_evpd_b0 },
	{ .page = 0xb1, .emulate = spc_emulate_evpd_b1 },
	{ .page = 0xb2, .emulate = spc_emulate_evpd_b2 },
	{ .page = 0xb3, .emulate = spc_emulate_evpd_b3 },
};

/* supported vital product data pages */
static sense_reason_t
spc_emulate_evpd_00(struct se_cmd *cmd, unsigned char *buf)
{
	int p;

	/*
	 * Only report the INQUIRY EVPD=1 pages after a valid NAA
	 * Registered Extended LUN WWN has been set via ConfigFS
	 * during device creation/restart.
	 */
	if (cmd->se_dev->dev_flags & DF_EMULATED_VPD_UNIT_SERIAL) {
		buf[3] = ARRAY_SIZE(evpd_handlers);
		for (p = 0; p < ARRAY_SIZE(evpd_handlers); ++p)
			buf[p + 4] = evpd_handlers[p].page;
	}

	return 0;
}

static sense_reason_t
spc_emulate_inquiry(struct se_cmd *cmd)
{
	struct se_device *dev = cmd->se_dev;
	struct se_portal_group *tpg = cmd->se_lun->lun_tpg;
	unsigned char *rbuf;
	unsigned char *cdb = cmd->t_task_cdb;
	unsigned char *buf;
	sense_reason_t ret;
	int p;
	int len = 0;

	buf = kzalloc(SE_INQUIRY_BUF, GFP_KERNEL);
	if (!buf) {
		pr_err("Unable to allocate response buffer for INQUIRY\n");
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	if (dev == rcu_access_pointer(tpg->tpg_virt_lun0->lun_se_dev))
		buf[0] = 0x3f; /* Not connected */
	else
		buf[0] = dev->transport->get_device_type(dev);

	if (!(cdb[1] & 0x1)) {
		if (cdb[2]) {
			pr_err("INQUIRY with EVPD==0 but PAGE CODE=%02x\n",
			       cdb[2]);
			ret = TCM_INVALID_CDB_FIELD;
			goto out;
		}

		ret = spc_emulate_inquiry_std(cmd, buf);
		len = buf[4] + 5;
		goto out;
	}

	for (p = 0; p < ARRAY_SIZE(evpd_handlers); ++p) {
		if (cdb[2] == evpd_handlers[p].page) {
			buf[1] = cdb[2];
			ret = evpd_handlers[p].emulate(cmd, buf);
			len = get_unaligned_be16(&buf[2]) + 4;
			goto out;
		}
	}

	pr_err("Unknown VPD Code: 0x%02x\n", cdb[2]);
	ret = TCM_INVALID_CDB_FIELD;

out:
	rbuf = transport_kmap_data_sg(cmd);
	if (rbuf) {
		memcpy(rbuf, buf, min_t(u32, SE_INQUIRY_BUF, cmd->data_length));
		transport_kunmap_data_sg(cmd);
	}
	kfree(buf);

	if (!ret)
		target_complete_cmd_with_length(cmd, GOOD, len);
	return ret;
}

static sense_reason_t
spc_emulate_read_format_capacity(struct se_cmd *cmd)
{
	//unsigned char *cdb = cmd->t_task_cdb;
	struct se_device *dev = cmd->se_dev;
	u64 blocks = dev->transport->get_blocks(dev);
	u32 block_size = dev->dev_attrib.block_size;
	unsigned char buf[12];
	unsigned char *rbuf;
	
	put_unaligned_be32(8, &buf[0]);
	put_unaligned_be32((u32)min_t(u64,blocks - 1,0xffffffffuLL), &buf[4]);
						/* Max logical block */
	put_unaligned_be32(block_size, &buf[8]);/* Block length */
	buf[8]=2;
	rbuf = transport_kmap_data_sg(cmd);
	if (rbuf) {
		memcpy(rbuf, buf, min_t(u32, 12, cmd->data_length));
		transport_kunmap_data_sg(cmd);
	}
	target_complete_cmd_with_length(cmd, GOOD, 12);
	return 0;
}

static int spc_modesense_rwrecovery(struct se_cmd *cmd, u8 pc, u8 *p)
{
	p[0] = 0x01;
	p[1] = 0x0a;

	/* No changeable values for now */
	if (pc == 1)
		goto out;

out:
	return 12;
}

static int spc_modesense_control(struct se_cmd *cmd, u8 pc, u8 *p)
{
	struct se_device *dev = cmd->se_dev;
	struct se_session *sess = cmd->se_sess;

	p[0] = 0x0a;
	p[1] = 0x0a;

	/* No changeable values for now */
	if (pc == 1)
		goto out;

	/* GLTSD: No implicit save of log parameters */
	p[2] = (1 << 1);
	if (target_sense_desc_format(dev))
		/* D_SENSE: Descriptor format sense data for 64bit sectors */
		p[2] |= (1 << 2);

	/*
	 * From spc4r23, 7.4.7 Control mode page
	 *
	 * The QUEUE ALGORITHM MODIFIER field (see table 368) specifies
	 * restrictions on the algorithm used for reordering commands
	 * having the SIMPLE task attribute (see SAM-4).
	 *
	 *                    Table 368 -- QUEUE ALGORITHM MODIFIER field
	 *                         Code      Description
	 *                          0h       Restricted reordering
	 *                          1h       Unrestricted reordering allowed
	 *                          2h to 7h    Reserved
	 *                          8h to Fh    Vendor specific
	 *
	 * A value of zero in the QUEUE ALGORITHM MODIFIER field specifies that
	 * the device server shall order the processing sequence of commands
	 * having the SIMPLE task attribute such that data integrity is maintained
	 * for that I_T nexus (i.e., if the transmission of new SCSI transport protocol
	 * requests is halted at any time, the final value of all data observable
	 * on the medium shall be the same as if all the commands had been processed
	 * with the ORDERED task attribute).
	 *
	 * A value of one in the QUEUE ALGORITHM MODIFIER field specifies that the
	 * device server may reorder the processing sequence of commands having the
	 * SIMPLE task attribute in any manner. Any data integrity exposures related to
	 * command sequence order shall be explicitly handled by the application client
	 * through the selection of appropriate ommands and task attributes.
	 */
	p[3] = (dev->dev_attrib.emulate_rest_reord == 1) ? 0x00 : 0x10;
	/*
	 * From spc4r17, section 7.4.6 Control mode Page
	 *
	 * Unit Attention interlocks control (UN_INTLCK_CTRL) to code 00b
	 *
	 * 00b: The logical unit shall clear any unit attention condition
	 * reported in the same I_T_L_Q nexus transaction as a CHECK CONDITION
	 * status and shall not establish a unit attention condition when a com-
	 * mand is completed with BUSY, TASK SET FULL, or RESERVATION CONFLICT
	 * status.
	 *
	 * 10b: The logical unit shall not clear any unit attention condition
	 * reported in the same I_T_L_Q nexus transaction as a CHECK CONDITION
	 * status and shall not establish a unit attention condition when
	 * a command is completed with BUSY, TASK SET FULL, or RESERVATION
	 * CONFLICT status.
	 *
	 * 11b a The logical unit shall not clear any unit attention condition
	 * reported in the same I_T_L_Q nexus transaction as a CHECK CONDITION
	 * status and shall establish a unit attention condition for the
	 * initiator port associated with the I_T nexus on which the BUSY,
	 * TASK SET FULL, or RESERVATION CONFLICT status is being returned.
	 * Depending on the status, the additional sense code shall be set to
	 * PREVIOUS BUSY STATUS, PREVIOUS TASK SET FULL STATUS, or PREVIOUS
	 * RESERVATION CONFLICT STATUS. Until it is cleared by a REQUEST SENSE
	 * command, a unit attention condition shall be established only once
	 * for a BUSY, TASK SET FULL, or RESERVATION CONFLICT status regardless
	 * to the number of commands completed with one of those status codes.
	 */
	p[4] = (dev->dev_attrib.emulate_ua_intlck_ctrl == 2) ? 0x30 :
	       (dev->dev_attrib.emulate_ua_intlck_ctrl == 1) ? 0x20 : 0x00;
	/*
	 * From spc4r17, section 7.4.6 Control mode Page
	 *
	 * Task Aborted Status (TAS) bit set to zero.
	 *
	 * A task aborted status (TAS) bit set to zero specifies that aborted
	 * tasks shall be terminated by the device server without any response
	 * to the application client. A TAS bit set to one specifies that tasks
	 * aborted by the actions of an I_T nexus other than the I_T nexus on
	 * which the command was received shall be completed with TASK ABORTED
	 * status (see SAM-4).
	 */
	p[5] = (dev->dev_attrib.emulate_tas) ? 0x40 : 0x00;
	/*
	 * From spc4r30, section 7.5.7 Control mode page
	 *
	 * Application Tag Owner (ATO) bit set to one.
	 *
	 * If the ATO bit is set to one the device server shall not modify the
	 * LOGICAL BLOCK APPLICATION TAG field and, depending on the protection
	 * type, shall not modify the contents of the LOGICAL BLOCK REFERENCE
	 * TAG field.
	 */
	if (sess->sup_prot_ops & (TARGET_PROT_DIN_PASS | TARGET_PROT_DOUT_PASS)) {
		if (dev->dev_attrib.pi_prot_type || sess->sess_prot_type)
			p[5] |= 0x80;
	}

	p[8] = 0xff;
	p[9] = 0xff;
	p[11] = 30;

out:
	return 12;
}

static int spc_modesense_caching(struct se_cmd *cmd, u8 pc, u8 *p)
{
	struct se_device *dev = cmd->se_dev;

	p[0] = 0x08;
	p[1] = 0x12;

	/* No changeable values for now */
	if (pc == 1)
		goto out;

	if (target_check_wce(dev))
		p[2] = 0x04; /* Write Cache Enable */
	p[12] = 0x20; /* Disabled Read Ahead */

out:
	return 20;
}

static int spc_modesense_informational_exceptions(struct se_cmd *cmd, u8 pc, unsigned char *p)
{
	p[0] = 0x1c;
	p[1] = 0x0a;

	/* No changeable values for now */
	if (pc == 1)
		goto out;

out:
	return 12;
}

static struct {
	uint8_t		page;
	uint8_t		subpage;
	int		(*emulate)(struct se_cmd *, u8, unsigned char *);
} modesense_handlers[] = {
	{ .page = 0x01, .subpage = 0x00, .emulate = spc_modesense_rwrecovery },
	{ .page = 0x08, .subpage = 0x00, .emulate = spc_modesense_caching },
	{ .page = 0x0a, .subpage = 0x00, .emulate = spc_modesense_control },
	{ .page = 0x1c, .subpage = 0x00, .emulate = spc_modesense_informational_exceptions },
};

static void spc_modesense_write_protect(unsigned char *buf, int type)
{
	/*
	 * I believe that the WP bit (bit 7) in the mode header is the same for
	 * all device types..
	 */
	switch (type) {
	case TYPE_DISK:
	case TYPE_TAPE:
	default:
		buf[0] |= 0x80; /* WP bit */
		break;
	}
}

static void spc_modesense_dpofua(unsigned char *buf, int type)
{
	switch (type) {
	case TYPE_DISK:
		buf[0] |= 0x10; /* DPOFUA bit */
		break;
	default:
		break;
	}
}

static int spc_modesense_blockdesc(unsigned char *buf, u64 blocks, u32 block_size)
{
	*buf++ = 8;
	put_unaligned_be32(min(blocks, 0xffffffffull), buf);
	buf += 4;
	put_unaligned_be32(block_size, buf);
	return 9;
}

static int spc_modesense_long_blockdesc(unsigned char *buf, u64 blocks, u32 block_size)
{
	if (blocks <= 0xffffffff)
		return spc_modesense_blockdesc(buf + 3, blocks, block_size) + 3;

	*buf++ = 1;		/* LONGLBA */
	buf += 2;
	*buf++ = 16;
	put_unaligned_be64(blocks, buf);
	buf += 12;
	put_unaligned_be32(block_size, buf);

	return 17;
}

static sense_reason_t spc_emulate_modesense(struct se_cmd *cmd)
{
	struct se_device *dev = cmd->se_dev;
	char *cdb = cmd->t_task_cdb;
	unsigned char buf[SE_MODE_PAGE_BUF], *rbuf;
	int type = dev->transport->get_device_type(dev);
	int ten = (cmd->t_task_cdb[0] == MODE_SENSE_10);
	bool dbd = !!(cdb[1] & 0x08);
	bool llba = ten ? !!(cdb[1] & 0x10) : false;
	u8 pc = cdb[2] >> 6;
	u8 page = cdb[2] & 0x3f;
	u8 subpage = cdb[3];
	int length = 0;
	int ret;
	int i;

	memset(buf, 0, SE_MODE_PAGE_BUF);

	/*
	 * Skip over MODE DATA LENGTH + MEDIUM TYPE fields to byte 3 for
	 * MODE_SENSE_10 and byte 2 for MODE_SENSE (6).
	 */
	length = ten ? 3 : 2;

	/* DEVICE-SPECIFIC PARAMETER */
	if (cmd->se_lun->lun_access_ro || target_lun_is_rdonly(cmd))
		spc_modesense_write_protect(&buf[length], type);

	/*
	 * SBC only allows us to enable FUA and DPO together.  Fortunately
	 * DPO is explicitly specified as a hint, so a noop is a perfectly
	 * valid implementation.
	 */
	if (target_check_fua(dev))
		spc_modesense_dpofua(&buf[length], type);

	++length;

	/* BLOCK DESCRIPTOR */

	/*
	 * For now we only include a block descriptor for disk (SBC)
	 * devices; other command sets use a slightly different format.
	 */
	if (!dbd && type == TYPE_DISK) {
		u64 blocks = dev->transport->get_blocks(dev);
		u32 block_size = dev->dev_attrib.block_size;

		if (ten) {
			if (llba) {
				length += spc_modesense_long_blockdesc(&buf[length],
								       blocks, block_size);
			} else {
				length += 3;
				length += spc_modesense_blockdesc(&buf[length],
								  blocks, block_size);
			}
		} else {
			length += spc_modesense_blockdesc(&buf[length], blocks,
							  block_size);
		}
	} else {
		if (ten)
			length += 4;
		else
			length += 1;
	}

	if (page == 0x3f) {
		if (subpage != 0x00 && subpage != 0xff) {
			pr_warn("MODE_SENSE: Invalid subpage code: 0x%02x\n", subpage);
			return TCM_INVALID_CDB_FIELD;
		}

		for (i = 0; i < ARRAY_SIZE(modesense_handlers); ++i) {
			/*
			 * Tricky way to say all subpage 00h for
			 * subpage==0, all subpages for subpage==0xff
			 * (and we just checked above that those are
			 * the only two possibilities).
			 */
			if ((modesense_handlers[i].subpage & ~subpage) == 0) {
				ret = modesense_handlers[i].emulate(cmd, pc, &buf[length]);
				if (!ten && length + ret >= 255)
					break;
				length += ret;
			}
		}

		goto set_length;
	}

	for (i = 0; i < ARRAY_SIZE(modesense_handlers); ++i)
		if (modesense_handlers[i].page == page &&
		    modesense_handlers[i].subpage == subpage) {
			length += modesense_handlers[i].emulate(cmd, pc, &buf[length]);
			goto set_length;
		}

	/*
	 * We don't intend to implement:
	 *  - obsolete page 03h "format parameters" (checked by Solaris)
	 */
	if (page != 0x03)
		pr_err("MODE SENSE: unimplemented page/subpage: 0x%02x/0x%02x\n",
		       page, subpage);

	return TCM_UNKNOWN_MODE_PAGE;

set_length:
	if (ten)
		put_unaligned_be16(length - 2, buf);
	else
		buf[0] = length - 1;

	rbuf = transport_kmap_data_sg(cmd);
	if (rbuf) {
		memcpy(rbuf, buf, min_t(u32, SE_MODE_PAGE_BUF, cmd->data_length));
		transport_kunmap_data_sg(cmd);
	}

	target_complete_cmd_with_length(cmd, GOOD, length);
	return 0;
}

static sense_reason_t spc_emulate_modeselect(struct se_cmd *cmd)
{
	char *cdb = cmd->t_task_cdb;
	bool ten = cdb[0] == MODE_SELECT_10;
	int off = ten ? 8 : 4;
	bool pf = !!(cdb[1] & 0x10);
	u8 page, subpage;
	unsigned char *buf;
	unsigned char tbuf[SE_MODE_PAGE_BUF];
	int length;
	sense_reason_t ret = 0;
	int i;

	if (!cmd->data_length) {
		target_complete_cmd(cmd, GOOD);
		return 0;
	}

	if (cmd->data_length < off + 2)
		return TCM_PARAMETER_LIST_LENGTH_ERROR;

	buf = transport_kmap_data_sg(cmd);
	if (!buf)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	if (!pf) {
		ret = TCM_INVALID_CDB_FIELD;
		goto out;
	}

	page = buf[off] & 0x3f;
	subpage = buf[off] & 0x40 ? buf[off + 1] : 0;

	for (i = 0; i < ARRAY_SIZE(modesense_handlers); ++i)
		if (modesense_handlers[i].page == page &&
		    modesense_handlers[i].subpage == subpage) {
			memset(tbuf, 0, SE_MODE_PAGE_BUF);
			length = modesense_handlers[i].emulate(cmd, 0, tbuf);
			goto check_contents;
		}

	ret = TCM_UNKNOWN_MODE_PAGE;
	goto out;

check_contents:
	if (cmd->data_length < off + length) {
		ret = TCM_PARAMETER_LIST_LENGTH_ERROR;
		goto out;
	}

	if (memcmp(buf + off, tbuf, length))
		ret = TCM_INVALID_PARAMETER_LIST;

out:
	transport_kunmap_data_sg(cmd);

	if (!ret)
		target_complete_cmd(cmd, GOOD);
	return ret;
}

static sense_reason_t spc_emulate_request_sense(struct se_cmd *cmd)
{
	unsigned char *cdb = cmd->t_task_cdb;
	unsigned char *rbuf;
	u8 ua_asc = 0, ua_ascq = 0;
	unsigned char buf[SE_SENSE_BUF];
	bool desc_format = target_sense_desc_format(cmd->se_dev);

	memset(buf, 0, SE_SENSE_BUF);

	if (cdb[1] & 0x01) {
		pr_err("REQUEST_SENSE description emulation not"
			" supported\n");
		return TCM_INVALID_CDB_FIELD;
	}

	rbuf = transport_kmap_data_sg(cmd);
	if (!rbuf)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	if (!core_scsi3_ua_clear_for_request_sense(cmd, &ua_asc, &ua_ascq))
		scsi_build_sense_buffer(desc_format, buf, UNIT_ATTENTION,
					ua_asc, ua_ascq);
	else
		scsi_build_sense_buffer(desc_format, buf, NO_SENSE, 0x0, 0x0);

	memcpy(rbuf, buf, min_t(u32, sizeof(buf), cmd->data_length));
	transport_kunmap_data_sg(cmd);

	target_complete_cmd(cmd, GOOD);
	return 0;
}

sense_reason_t spc_emulate_report_luns(struct se_cmd *cmd)
{
	struct se_dev_entry *deve;
	struct se_session *sess = cmd->se_sess;
	struct se_node_acl *nacl;
	struct scsi_lun slun;
	unsigned char *buf;
	u32 lun_count = 0, offset = 8;
	__be32 len;

	buf = transport_kmap_data_sg(cmd);
	if (cmd->data_length && !buf)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	/*
	 * If no struct se_session pointer is present, this struct se_cmd is
	 * coming via a target_core_mod PASSTHROUGH op, and not through
	 * a $FABRIC_MOD.  In that case, report LUN=0 only.
	 */
	if (!sess)
		goto done;

	nacl = sess->se_node_acl;

	rcu_read_lock();
	hlist_for_each_entry_rcu(deve, &nacl->lun_entry_hlist, link) {
		/*
		 * We determine the correct LUN LIST LENGTH even once we
		 * have reached the initial allocation length.
		 * See SPC2-R20 7.19.
		 */
		lun_count++;
		if (offset >= cmd->data_length)
			continue;

		int_to_scsilun(deve->mapped_lun, &slun);
		memcpy(buf + offset, &slun,
		       min(8u, cmd->data_length - offset));
		offset += 8;
	}
	rcu_read_unlock();

	/*
	 * See SPC3 r07, page 159.
	 */
done:
	/*
	 * If no LUNs are accessible, report virtual LUN 0.
	 */
	if (lun_count == 0) {
		int_to_scsilun(0, &slun);
		if (cmd->data_length > 8)
			memcpy(buf + offset, &slun,
			       min(8u, cmd->data_length - offset));
		lun_count = 1;
	}

	if (buf) {
		len = cpu_to_be32(lun_count * 8);
		memcpy(buf, &len, min_t(int, sizeof len, cmd->data_length));
		transport_kunmap_data_sg(cmd);
	}

	target_complete_cmd_with_length(cmd, GOOD, 8 + lun_count * 8);
	return 0;
}
EXPORT_SYMBOL(spc_emulate_report_luns);

static sense_reason_t
spc_emulate_testunitready(struct se_cmd *cmd)
{
	target_complete_cmd(cmd, GOOD);
	return 0;
}

////////////////////////
//begin of scst code from http://scst.sourceforge.net/
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
//#ifndef __aligned
//#define __aligned(x) __attribute__((aligned(x)))
//#endif
//#ifndef __packed
//#define __packed __attribute__((packed))
//#endif
//#endif
#define SCST_DEFAULT_TIMEOUT			(30 * HZ)
#define SCST_DEFAULT_NOMINAL_TIMEOUT_SEC	1

#define SCST_GENERIC_CHANGER_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_CHANGER_LONG_TIMEOUT	(14000 * HZ)

#define SCST_GENERIC_PROCESSOR_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_PROCESSOR_LONG_TIMEOUT	(14000 * HZ)

#define SCST_GENERIC_TAPE_SMALL_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_TAPE_REG_TIMEOUT		(900 * HZ)
#define SCST_GENERIC_TAPE_LONG_TIMEOUT		(14000 * HZ)

#define SCST_GENERIC_MODISK_SMALL_TIMEOUT	(3 * HZ)
#define SCST_GENERIC_MODISK_REG_TIMEOUT		(900 * HZ)
#define SCST_GENERIC_MODISK_LONG_TIMEOUT	(14000 * HZ)

#define SCST_GENERIC_DISK_SMALL_TIMEOUT		(10 * HZ)
#define SCST_GENERIC_DISK_REG_TIMEOUT		(60 * HZ)
#define SCST_GENERIC_DISK_LONG_TIMEOUT		(3600 * HZ)

#define SCST_GENERIC_RAID_TIMEOUT		(3 * HZ)
#define SCST_GENERIC_RAID_LONG_TIMEOUT		(14000 * HZ)

#define SCST_GENERIC_CDROM_SMALL_TIMEOUT	(3 * HZ)
#define SCST_GENERIC_CDROM_REG_TIMEOUT		(900 * HZ)
#define SCST_GENERIC_CDROM_LONG_TIMEOUT		(14000 * HZ)

#define SCST_MAX_OTHER_TIMEOUT			(14000 * HZ)

#define VDEV_DEF_RDPROTECT	0xE0
#define VDEV_DEF_WRPROTECT	0xE0
#define VDEV_DEF_VRPROTECT	0xE0
#define VDEF_DEF_GROUP_NUM	0

#define SCST_OD_DEFAULT_CONTROL_BYTE     4

#define SUBCODE_READ_32		0x09
#define SUBCODE_VERIFY_32	0x0a
#define SUBCODE_WRITE_32	0x0b
#define SUBCODE_WRITE_VERIFY_32	0x0c
#define SUBCODE_WRITE_SAME_32	0x0d

struct scst_opcode_descriptor {
	uint16_t od_serv_action;
	uint8_t od_opcode;
	uint8_t od_serv_action_valid:1;
	uint8_t od_support:3; /* SUPPORT bits */
	uint16_t od_cdb_size;
	uint8_t od_comm_specific_timeout;
	uint32_t od_nominal_timeout;
	uint32_t od_recommended_timeout;
	uint8_t od_cdb_usage_bits[];
} __packed;

const struct scst_opcode_descriptor scst_op_descr_inquiry = {
	.od_opcode = INQUIRY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { INQUIRY, 1, 0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_inquiry);

const struct scst_opcode_descriptor scst_op_descr_extended_copy = {
	.od_opcode = EXTENDED_COPY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { EXTENDED_COPY, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_extended_copy);

const struct scst_opcode_descriptor scst_op_descr_tur = {
	.od_opcode = TEST_UNIT_READY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { TEST_UNIT_READY, 0, 0, 0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_tur);

const struct scst_opcode_descriptor scst_op_descr_log_select = {
	.od_opcode = LOG_SELECT,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { LOG_SELECT, 3, 0xFF, 0xFF, 0, 0, 0, 0xFF, 0xFF,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_log_select);

const struct scst_opcode_descriptor scst_op_descr_log_sense = {
	.od_opcode = LOG_SENSE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { LOG_SENSE, 1, 0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_log_sense);

const struct scst_opcode_descriptor scst_op_descr_mode_select6 = {
	.od_opcode = MODE_SELECT,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MODE_SELECT, 0x11, 0, 0, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_mode_select6);

const struct scst_opcode_descriptor scst_op_descr_mode_sense6 = {
	.od_opcode = MODE_SENSE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MODE_SENSE, 8, 0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_mode_sense6);

const struct scst_opcode_descriptor scst_op_descr_mode_select10 = {
	.od_opcode = MODE_SELECT_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MODE_SELECT_10, 0x11, 0, 0, 0, 0, 0, 0xFF, 0xFF,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_mode_select10);

const struct scst_opcode_descriptor scst_op_descr_mode_sense10 = {
	.od_opcode = MODE_SENSE_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MODE_SENSE_10, 0x18, 0xFF, 0xFF, 0, 0, 0, 0xFF, 0xFF,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_mode_sense10);

const struct scst_opcode_descriptor scst_op_descr_rtpg = {
	.od_opcode = MAINTENANCE_IN,
	.od_serv_action = MI_REPORT_TARGET_PGS,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MAINTENANCE_IN, 0xE0|MI_REPORT_TARGET_PGS, 0, 0,
			       0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_rtpg);

const struct scst_opcode_descriptor scst_op_descr_stpg = {
	.od_opcode = MAINTENANCE_OUT,
	.od_serv_action = MO_SET_TARGET_PGS,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MAINTENANCE_OUT, MO_SET_TARGET_PGS, 0, 0, 0, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_stpg);

const struct scst_opcode_descriptor scst_op_descr_send_diagnostic = {
	.od_opcode = SEND_DIAGNOSTIC,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SEND_DIAGNOSTIC, 0xF7, 0, 0xFF, 0xFF,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_send_diagnostic);

const struct scst_opcode_descriptor scst_op_descr_reserve6 = {
	.od_opcode = RESERVE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { RESERVE, 0, 0, 0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_reserve6);

const struct scst_opcode_descriptor scst_op_descr_release6 = {
	.od_opcode = RELEASE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { RELEASE, 0, 0, 0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_release6);

const struct scst_opcode_descriptor scst_op_descr_reserve10 = {
	.od_opcode = RESERVE_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { RESERVE_10, 0, 0, 0, 0, 0, 0, 0, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_reserve10);

const struct scst_opcode_descriptor scst_op_descr_release10 = {
	.od_opcode = RELEASE_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { RELEASE_10, 0, 0, 0, 0, 0, 0, 0, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_release10);

const struct scst_opcode_descriptor scst_op_descr_pr_in = {
	.od_opcode = PERSISTENT_RESERVE_IN,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { PERSISTENT_RESERVE_IN, 0x1F, 0, 0, 0, 0, 0, 0xFF, 0xFF,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_pr_in);

const struct scst_opcode_descriptor scst_op_descr_pr_out = {
	.od_opcode = PERSISTENT_RESERVE_OUT,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { PERSISTENT_RESERVE_OUT, 0x1F, 0xFF, 0, 0, 0xFF,
			       0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_pr_out);

const struct scst_opcode_descriptor scst_op_descr_report_luns = {
	.od_opcode = REPORT_LUNS,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { REPORT_LUNS, 0, 0xFF, 0, 0, 0, 0xFF, 0xFF,
			       0xFF, 0xFF, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_report_luns);

const struct scst_opcode_descriptor scst_op_descr_request_sense = {
	.od_opcode = REQUEST_SENSE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { REQUEST_SENSE, 1, 0, 0, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_request_sense);

const struct scst_opcode_descriptor scst_op_descr_report_supp_tm_fns = {
	.od_opcode = MAINTENANCE_IN,
	.od_serv_action = MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MAINTENANCE_IN, MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS,
			       0x80, 0, 0, 0, 0xFF, 0xFF, 0xFF,
			       0xFF, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_report_supp_tm_fns);

const struct scst_opcode_descriptor scst_op_descr_report_supp_opcodes = {
	.od_opcode = MAINTENANCE_IN,
	.od_serv_action = MI_REPORT_SUPPORTED_OPERATION_CODES,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { MAINTENANCE_IN, MI_REPORT_SUPPORTED_OPERATION_CODES,
			       0x87, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};
EXPORT_SYMBOL(scst_op_descr_report_supp_opcodes);

static const struct scst_opcode_descriptor scst_op_descr_cwr = {
	.od_opcode = COMPARE_AND_WRITE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { COMPARE_AND_WRITE, VDEV_DEF_WRPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0, 0, 0, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_format_unit = {
	.od_opcode = FORMAT_UNIT,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_LONG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { FORMAT_UNIT, 0xF0, 0, 0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};

#if 0
static const struct scst_opcode_descriptor scst_op_descr_get_lba_status = {
	.od_opcode = SERVICE_ACTION_IN_16,
	.od_serv_action = SAI_GET_LBA_STATUS,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SERVICE_ACTION_IN_16, SAI_GET_LBA_STATUS,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};
#endif

static const struct scst_opcode_descriptor scst_op_descr_allow_medium_removal = {
	.od_opcode = ALLOW_MEDIUM_REMOVAL,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { ALLOW_MEDIUM_REMOVAL, 0, 0, 0, 3, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read6 = {
	.od_opcode = READ_6,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_6, 0x1F,
			       0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read10 = {
	.od_opcode = READ_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_10, VDEV_DEF_RDPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read12 = {
	.od_opcode = READ_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_12, VDEV_DEF_RDPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read16 = {
	.od_opcode = READ_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_16, VDEV_DEF_RDPROTECT | 0x18,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_READ_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_READ_32, VDEV_DEF_RDPROTECT | 0x18, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_read_capacity = {
	.od_opcode = READ_CAPACITY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_CAPACITY, 0, 0, 0, 0, 0, 0,
			       0, 0, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_read_capacity16 = {
	.od_opcode = SERVICE_ACTION_IN_16,
	.od_serv_action = SAI_READ_CAPACITY_16,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SERVICE_ACTION_IN_16, SAI_READ_CAPACITY_16,
			       0, 0, 0, 0, 0, 0, 0, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_start_stop_unit = {
	.od_opcode = START_STOP,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_SMALL_TIMEOUT/HZ,
	.od_cdb_usage_bits = { START_STOP, 1, 0, 0xF, 0xF7, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_sync_cache10 = {
	.od_opcode = SYNCHRONIZE_CACHE,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SYNCHRONIZE_CACHE, 2,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_sync_cache16 = {
	.od_opcode = SYNCHRONIZE_CACHE_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { SYNCHRONIZE_CACHE_16, 2,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_unmap = {
	.od_opcode = UNMAP,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { UNMAP, 0, 0, 0, 0, 0, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify10 = {
	.od_opcode = VERIFY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VERIFY, VDEV_DEF_VRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify12 = {
	.od_opcode = VERIFY_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VERIFY_12, VDEV_DEF_VRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify16 = {
	.od_opcode = VERIFY_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VERIFY_16, VDEV_DEF_VRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_verify32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_VERIFY_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_VERIFY_32, VDEV_DEF_VRPROTECT | 0x16, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_write6 = {
	.od_opcode = WRITE_6,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 6,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_6, 0x1F,
			       0xFF, 0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write10 = {
	.od_opcode = WRITE_10,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_10, VDEV_DEF_WRPROTECT | 0x1A,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write12 = {
	.od_opcode = WRITE_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_12, VDEV_DEF_WRPROTECT | 0x1A,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write16 = {
	.od_opcode = WRITE_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_16, VDEV_DEF_WRPROTECT | 0x1A,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_WRITE_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_WRITE_32, VDEV_DEF_WRPROTECT | 0x1A, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify10 = {
	.od_opcode = WRITE_VERIFY,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_VERIFY, VDEV_DEF_WRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify12 = {
	.od_opcode = WRITE_VERIFY_12,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 12,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_VERIFY_12, VDEV_DEF_WRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       VDEF_DEF_GROUP_NUM, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify16 = {
	.od_opcode = WRITE_VERIFY_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_VERIFY_16, VDEV_DEF_WRPROTECT | 0x16,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_verify32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_WRITE_VERIFY_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_WRITE_VERIFY_32, VDEV_DEF_WRPROTECT | 0x16, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_write_same10 = {
	.od_opcode = WRITE_SAME,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_SAME, VDEV_DEF_WRPROTECT | 0x8,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_same16 = {
	.od_opcode = WRITE_SAME_16,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 16,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { WRITE_SAME_16, VDEV_DEF_WRPROTECT | 0x8,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, VDEF_DEF_GROUP_NUM,
			       SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor scst_op_descr_write_same32 = {
	.od_opcode = VARIABLE_LENGTH_CMD,
	.od_serv_action = SUBCODE_WRITE_SAME_32,
	.od_serv_action_valid = 1,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 32,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { VARIABLE_LENGTH_CMD, SCST_OD_DEFAULT_CONTROL_BYTE,
			       0, 0, 0, 0, VDEF_DEF_GROUP_NUM, 0x18, 0,
			       SUBCODE_WRITE_SAME_32, VDEV_DEF_WRPROTECT | 0x8, 0,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF },
};

static const struct scst_opcode_descriptor scst_op_descr_read_toc = {
	.od_opcode = READ_TOC,
	.od_support = 3, /* supported as in the standard */
	.od_cdb_size = 10,
	.od_nominal_timeout = SCST_DEFAULT_NOMINAL_TIMEOUT_SEC,
	.od_recommended_timeout = SCST_GENERIC_DISK_REG_TIMEOUT/HZ,
	.od_cdb_usage_bits = { READ_TOC, 0, 0xF, 0, 0, 0, 0xFF,
			       0xFF, 0xFF, SCST_OD_DEFAULT_CONTROL_BYTE },
};

static const struct scst_opcode_descriptor* g_all_supported_opcodes[]={
	&scst_op_descr_inquiry,
	&scst_op_descr_tur,
	&scst_op_descr_reserve6,
	&scst_op_descr_release6,
	&scst_op_descr_reserve10,
	&scst_op_descr_release10,
	&scst_op_descr_pr_in,
	&scst_op_descr_pr_out,
	&scst_op_descr_report_luns,
	&scst_op_descr_request_sense,
	&scst_op_descr_report_supp_opcodes,
	//&scst_op_descr_report_supp_tm_fns,

	&scst_op_descr_sync_cache10,
	&scst_op_descr_sync_cache16,
	&scst_op_descr_mode_sense6,
	&scst_op_descr_mode_sense10,
	&scst_op_descr_mode_select6,
	&scst_op_descr_mode_select10,
	&scst_op_descr_log_select,
	&scst_op_descr_log_sense,
	&scst_op_descr_start_stop_unit,
	&scst_op_descr_read_capacity,
	&scst_op_descr_send_diagnostic,
	&scst_op_descr_rtpg,
	&scst_op_descr_read6,
	&scst_op_descr_read10,
	&scst_op_descr_read12,
	&scst_op_descr_read16,
	&scst_op_descr_write6,
	&scst_op_descr_write10,
	&scst_op_descr_write12,
	&scst_op_descr_write16,
	&scst_op_descr_write_verify10,
	&scst_op_descr_write_verify12,
	&scst_op_descr_write_verify16,
	&scst_op_descr_verify10,
	&scst_op_descr_verify12,
	&scst_op_descr_verify16,
	&scst_op_descr_read_capacity16,
	&scst_op_descr_write_same10,
	&scst_op_descr_write_same16,
	&scst_op_descr_unmap,
	&scst_op_descr_format_unit,
	&scst_op_descr_extended_copy,
	&scst_op_descr_cwr,
	&scst_op_descr_stpg, 
};

static sense_reason_t scst_report_supported_opcodes(struct se_cmd *cmd)
{
	int length, buf_len, i, offs;
	uint8_t *buf;
	bool inline_buf;
	bool rctd = cmd->t_task_cdb[2] >> 7;
	int options = cmd->t_task_cdb[2] & 7;
	int req_opcode = cmd->t_task_cdb[3];
	int req_sa = get_unaligned_be16(&cmd->t_task_cdb[4]);
	const struct scst_opcode_descriptor *op = NULL;
	const struct scst_opcode_descriptor **supp_opcodes = g_all_supported_opcodes;
	int supp_opcodes_cnt=sizeof(g_all_supported_opcodes)/sizeof(struct scst_opcode_descriptor*);

	//TRACE_ENTRY();

	//TRACE_DBG("cmd %p, options %d, req_opcode %x, req_sa %x, rctd %d",
	//	cmd, options, req_opcode, req_sa, rctd);

	switch (options) {
	case 0: /* all */
		buf_len = 4;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			buf_len += 8;
			if (rctd)
				buf_len += 12;
		}
		break;
	case 1:
		buf_len = 0;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			if (req_opcode == supp_opcodes[i]->od_opcode) {
				op = supp_opcodes[i];
				if (op->od_serv_action_valid) {
					//TRACE(TRACE_MINOR, "Requested opcode %x "
					//	"with unexpected service action "
					//	"(dev %s, initiator %s)",
					//	req_opcode, cmd->dev->virt_name,
					//	cmd->sess->initiator_name);
					return TCM_INVALID_CDB_FIELD;
				}
				buf_len = 4 + op->od_cdb_size;
				if (rctd)
					buf_len += 12;
				break;
			}
		}
		if (op == NULL) {
			//TRACE(TRACE_MINOR, "Requested opcode %x not found "
			//	"(dev %s, initiator %s)", req_opcode,
			//	cmd->dev->virt_name, cmd->sess->initiator_name);
			buf_len = 4;
		}
		break;
	case 2:
		buf_len = 0;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			if (req_opcode == supp_opcodes[i]->od_opcode) {
				op = supp_opcodes[i];
				if (!op->od_serv_action_valid) {
					//TRACE(TRACE_MINOR, "Requested opcode %x "
					//	"without expected service action "
					//	"(dev %s, initiator %s)",
					//	req_opcode, cmd->dev->virt_name,
					//	cmd->sess->initiator_name);
					return TCM_INVALID_CDB_FIELD;
				}
				if (req_sa != op->od_serv_action) {
					op = NULL; /* reset it */
					continue;
				}
				buf_len = 4 + op->od_cdb_size;
				if (rctd)
					buf_len += 12;
				break;
			}
		}
		if (op == NULL) {
			//TRACE(TRACE_MINOR, "Requested opcode %x/%x not found "
			//	"(dev %s, initiator %s)", req_opcode, req_sa,
			//	cmd->dev->virt_name, cmd->sess->initiator_name);
			buf_len = 4;
		}
		break;
	default:
		pr_err("REPORT SUPPORTED OPERATION CODES: REPORTING OPTIONS "
			"%x not supported", options);
		return TCM_INVALID_CDB_FIELD;
	}

	length = cmd->data_length;
	//TRACE_DBG("length %d, buf_len %d, op %p", length, buf_len, op);
	if (unlikely(length <= 0)){
		return TCM_PARAMETER_LIST_LENGTH_ERROR;
	}

	if (length >= buf_len) {
		buf = transport_kmap_data_sg(cmd);
		if (!buf)
			return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		inline_buf = true;
	} else {
		return TCM_PARAMETER_LIST_LENGTH_ERROR;
	}

	memset(buf, 0, buf_len);

	switch (options) {
	case 0: /* all */
		put_unaligned_be32(buf_len - 4, &buf[0]);
		offs = 4;
		for (i = 0; i < supp_opcodes_cnt; i++) {
			op = supp_opcodes[i];
			buf[offs] = op->od_opcode;
			if (op->od_serv_action_valid) {
				put_unaligned_be16(op->od_serv_action, &buf[offs + 2]);
				buf[offs + 5] |= 1;
			}
			put_unaligned_be16(op->od_cdb_size, &buf[offs + 6]);
			offs += 8;
			if (rctd) {
				buf[(offs - 8) + 5] |= 2;
				buf[offs + 1] = 0xA;
				buf[offs + 3] = op->od_comm_specific_timeout;
				put_unaligned_be32(op->od_nominal_timeout, &buf[offs + 4]);
				put_unaligned_be32(op->od_recommended_timeout, &buf[offs + 8]);
				offs += 12;
			}
		}
		break;
	case 1:
	case 2:
		if (op != NULL) {
			buf[1] |= op->od_support;
			put_unaligned_be16(op->od_cdb_size, &buf[2]);
			memcpy(&buf[4], op->od_cdb_usage_bits, op->od_cdb_size);
			if (rctd) {
				buf[1] |= 0x80;
				offs = 4 + op->od_cdb_size;
				buf[offs + 1] = 0xA;
				buf[offs + 3] = op->od_comm_specific_timeout;
				put_unaligned_be32(op->od_nominal_timeout, &buf[offs + 4]);
				put_unaligned_be32(op->od_recommended_timeout, &buf[offs + 8]);
			}
		}
		break;
	default:
		pr_err("scst: impossible %s %d\n",__FILE__,__LINE__);
	}

	if (length > buf_len)
		length = buf_len;

	transport_kunmap_data_sg(cmd);
	target_complete_cmd_with_length(cmd,GOOD,length);
	return 0;
}

////////////////////////

sense_reason_t
spc_parse_cdb(struct se_cmd *cmd, unsigned int *size)
{
	struct se_device *dev = cmd->se_dev;
	unsigned char *cdb = cmd->t_task_cdb;

	if (!dev->dev_attrib.emulate_pr &&
	    ((cdb[0] == PERSISTENT_RESERVE_IN) ||
	     (cdb[0] == PERSISTENT_RESERVE_OUT) ||
	     (cdb[0] == RELEASE || cdb[0] == RELEASE_10) ||
	     (cdb[0] == RESERVE || cdb[0] == RESERVE_10))) {
		return TCM_UNSUPPORTED_SCSI_OPCODE;
	}

	switch (cdb[0]) {
	case MODE_SELECT:
		*size = cdb[4];
		cmd->execute_cmd = spc_emulate_modeselect;
		break;
	case MODE_SELECT_10:
		*size = get_unaligned_be16(&cdb[7]);
		cmd->execute_cmd = spc_emulate_modeselect;
		break;
	case MODE_SENSE:
		*size = cdb[4];
		cmd->execute_cmd = spc_emulate_modesense;
		break;
	case MODE_SENSE_10:
		*size = get_unaligned_be16(&cdb[7]);
		cmd->execute_cmd = spc_emulate_modesense;
		break;
	case LOG_SELECT:
	case LOG_SENSE:
		*size = get_unaligned_be16(&cdb[7]);
		break;
	case PERSISTENT_RESERVE_IN:
		*size = get_unaligned_be16(&cdb[7]);
		cmd->execute_cmd = target_scsi3_emulate_pr_in;
		break;
	case PERSISTENT_RESERVE_OUT:
		*size = get_unaligned_be32(&cdb[5]);
		cmd->execute_cmd = target_scsi3_emulate_pr_out;
		break;
	case RELEASE:
	case RELEASE_10:
		if (cdb[0] == RELEASE_10)
			*size = get_unaligned_be16(&cdb[7]);
		else
			*size = cmd->data_length;

		cmd->execute_cmd = target_scsi2_reservation_release;
		break;
	case RESERVE:
	case RESERVE_10:
		/*
		 * The SPC-2 RESERVE does not contain a size in the SCSI CDB.
		 * Assume the passthrough or $FABRIC_MOD will tell us about it.
		 */
		if (cdb[0] == RESERVE_10)
			*size = get_unaligned_be16(&cdb[7]);
		else
			*size = cmd->data_length;

		cmd->execute_cmd = target_scsi2_reservation_reserve;
		break;
	case REQUEST_SENSE:
		*size = cdb[4];
		cmd->execute_cmd = spc_emulate_request_sense;
		break;
	case INQUIRY:
		*size = get_unaligned_be16(&cdb[3]);

		/*
		 * Do implicit HEAD_OF_QUEUE processing for INQUIRY.
		 * See spc4r17 section 5.3
		 */
		cmd->sam_task_attr = TCM_HEAD_TAG;
		cmd->execute_cmd = spc_emulate_inquiry;
		break;
	case READ_FORMAT_CAPACITIES:
		*size = get_unaligned_be16(&cdb[7]);
		cmd->execute_cmd = spc_emulate_read_format_capacity;
		break;
	case SECURITY_PROTOCOL_IN:
	case SECURITY_PROTOCOL_OUT:
		*size = get_unaligned_be32(&cdb[6]);
		break;
	case EXTENDED_COPY:
		*size = get_unaligned_be32(&cdb[10]);
		cmd->execute_cmd = target_do_xcopy;
		break;
	case RECEIVE_COPY_RESULTS:
		*size = get_unaligned_be32(&cdb[10]);
		cmd->execute_cmd = target_do_receive_copy_results;
		break;
	case READ_ATTRIBUTE:
	case WRITE_ATTRIBUTE:
		*size = get_unaligned_be32(&cdb[10]);
		break;
	case RECEIVE_DIAGNOSTIC:
	case SEND_DIAGNOSTIC:
		*size = get_unaligned_be16(&cdb[3]);
		break;
	case WRITE_BUFFER:
		*size = get_unaligned_be24(&cdb[6]);
		break;
	case REPORT_LUNS:
		cmd->execute_cmd = spc_emulate_report_luns;
		*size = get_unaligned_be32(&cdb[6]);
		/*
		 * Do implicit HEAD_OF_QUEUE processing for REPORT_LUNS
		 * See spc4r17 section 5.3
		 */
		cmd->sam_task_attr = TCM_HEAD_TAG;
		break;
	case TEST_UNIT_READY:
		cmd->execute_cmd = spc_emulate_testunitready;
		*size = 0;
		break;
	case MAINTENANCE_IN:
		if (dev->transport->get_device_type(dev) != TYPE_ROM) {
			/*
			 * MAINTENANCE_IN from SCC-2
			 * Check for emulated MI_REPORT_TARGET_PGS
			 */
			if ((cdb[1] & 0x1f) == MI_REPORT_TARGET_PGS) {
				cmd->execute_cmd =
					target_emulate_report_target_port_groups;
			}else if ((cdb[1] & 0x1f) == MI_REPORT_SUPPORTED_OPERATION_CODES) {
				cmd->execute_cmd =
					scst_report_supported_opcodes;
			}
			*size = get_unaligned_be32(&cdb[6]);
		} else {
			/*
			 * GPCMD_SEND_KEY from multi media commands
			 */
			*size = get_unaligned_be16(&cdb[8]);
		}
		break;
	case MAINTENANCE_OUT:
		if (dev->transport->get_device_type(dev) != TYPE_ROM) {
			/*
			 * MAINTENANCE_OUT from SCC-2
			 * Check for emulated MO_SET_TARGET_PGS.
			 */
			if (cdb[1] == MO_SET_TARGET_PGS) {
				cmd->execute_cmd =
					target_emulate_set_target_port_groups;
			}
			*size = get_unaligned_be32(&cdb[6]);
		} else {
			/*
			 * GPCMD_SEND_KEY from multi media commands
			 */
			*size = get_unaligned_be16(&cdb[8]);
		}
		break;
	default:
		return TCM_UNSUPPORTED_SCSI_OPCODE;
	}

	return 0;
}
EXPORT_SYMBOL(spc_parse_cdb);
