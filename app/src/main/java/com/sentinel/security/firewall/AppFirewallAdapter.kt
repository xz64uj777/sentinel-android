/*
 * Sentinel Android v2
 * Copyright (c) 2026 Kyle T.
 * All Rights Reserved.
 */
package com.sentinel.security.firewall

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.sentinel.security.databinding.RowAppFirewallBinding

class AppFirewallAdapter(
    private val onToggle: (String, Boolean) -> Unit
) : RecyclerView.Adapter<AppFirewallAdapter.AppViewHolder>() {

    private var allItems: List<FirewallApp> = emptyList()
    private var visibleItems: List<FirewallApp> = emptyList()
    private val selected = linkedSetOf<String>()

    fun submit(items: List<FirewallApp>, selectedPackages: Set<String>) {
        allItems = items
        visibleItems = items
        selected.clear()
        selected.addAll(selectedPackages)
        notifyDataSetChanged()
    }

    fun filter(query: String) {
        val normalized = query.trim().lowercase()
        visibleItems = if (normalized.isBlank()) {
            allItems
        } else {
            allItems.filter {
                it.label.lowercase().contains(normalized) ||
                    it.packageName.lowercase().contains(normalized)
            }
        }
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        val binding = RowAppFirewallBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return AppViewHolder(binding)
    }

    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        holder.bind(visibleItems[position])
    }

    override fun getItemCount(): Int = visibleItems.size

    inner class AppViewHolder(
        private val binding: RowAppFirewallBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(item: FirewallApp) {
            binding.txtAppLabel.text = item.label
            binding.txtPackageName.text = item.packageName
            binding.checkBlocked.setOnCheckedChangeListener(null)
            binding.checkBlocked.isChecked = item.packageName in selected
            binding.checkBlocked.setOnCheckedChangeListener { _, checked ->
                if (checked) selected += item.packageName else selected -= item.packageName
                onToggle(item.packageName, checked)
            }
            binding.root.setOnClickListener {
                binding.checkBlocked.isChecked = !binding.checkBlocked.isChecked
            }
        }
    }
}
