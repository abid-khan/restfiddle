/*
 * Copyright 2014 Ranjan Kumar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.restfiddle.security;

import java.util.List;

import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.stereotype.Component;

/**
 * @author abidk
 * 
 */
@Component
public class AclUtil {

    private MutableAclService mutableAclService;

    /**
     * @param oid
     * @param recipient
     * @param permission
     * @return
     */
    public boolean hasPermission(ObjectIdentity oid, Sid recipient, Permission permission) {

	MutableAcl acl;
	try {
	    acl = (MutableAcl) mutableAclService.readAclById(oid);
	} catch (NotFoundException nfe) {
	    acl = mutableAclService.createAcl(oid);
	}

	boolean hasPermission = false;
	List<AccessControlEntry> entries = acl.getEntries();
	for (int i = 0; i < entries.size(); i++) {
	    if (entries.get(i).getSid().equals(recipient) && entries.get(i).getPermission().equals(permission)) {
		hasPermission = true;
	    }
	}

	return hasPermission;
    }

    /**
     * @param oid
     * @param recipient
     * @param permission
     */
    public void grantPermission(ObjectIdentity oid, Sid recipient, Permission permission) {
	MutableAcl acl;

	try {
	    acl = (MutableAcl) mutableAclService.readAclById(oid);
	} catch (NotFoundException nfe) {
	    acl = mutableAclService.createAcl(oid);
	}

	acl.insertAce(acl.getEntries().size(), permission, recipient, true);
	mutableAclService.updateAcl(acl);
    }

    /**
     * @param oid
     * @param recipient
     * @param permission
     */
    public void revokePermission(ObjectIdentity oid, Sid recipient, Permission permission) {
	MutableAcl acl = (MutableAcl) mutableAclService.readAclById(oid);

	List<AccessControlEntry> entries = acl.getEntries();
	for (int i = 0; i < entries.size(); i++) {
	    if (entries.get(i).getSid().equals(recipient) && entries.get(i).getPermission().equals(permission)) {
		acl.deleteAce(i);
	    }
	}

	mutableAclService.updateAcl(acl);
    }

    /**
     * @param oid
     * @param recipient
     */
    public void grantAllPermissions(ObjectIdentity oid, Sid recipient) {
	if (!hasPermission(oid, recipient, BasePermission.ADMINISTRATION)) {
	    grantPermission(oid, recipient, BasePermission.ADMINISTRATION);
	}
	if (!hasPermission(oid, recipient, BasePermission.DELETE)) {
	    grantPermission(oid, recipient, BasePermission.DELETE);
	}
	if (!hasPermission(oid, recipient, BasePermission.WRITE)) {
	    grantPermission(oid, recipient, BasePermission.WRITE);
	}
	if (!hasPermission(oid, recipient, BasePermission.READ)) {
	    grantPermission(oid, recipient, BasePermission.READ);
	}
    }
}
