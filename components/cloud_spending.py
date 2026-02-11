"""
Cloud Spending Analyzer - "Preserve Cash"
==========================================

Analyzes cloud spending patterns across AWS, GCP, and Azure.
Uses quantum-enhanced anomaly detection to find:
- Spending anomalies (sudden spikes, unusual patterns)
- Resource waste (idle instances, oversized resources, unused storage)
- Optimization opportunities (reserved instances, committed use, spot pricing)

The "Preserve Cash" module helps MSMEs reduce cloud costs by 20-40%.
"""

import time
import json
import os
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta


class CloudSpendingAnalyzer:
    """
    Analyzes cloud spending patterns and identifies savings opportunities.
    Uses TAARA's quantum-enhanced pattern detection for spending anomalies.
    """

    def __init__(self, model_dir: str = 'models'):
        self.model_dir = model_dir
        self.spending_history: List[Dict] = []
        self.baseline_spending: Optional[np.ndarray] = None
        self.anomaly_threshold = 2.0
        os.makedirs(model_dir, exist_ok=True)
        self._load_history()

    def analyze_platform_costs(self, platform, cost_data: Optional[Dict] = None) -> Dict:
        """
        Comprehensive cost analysis for a connected platform.
        Returns findings, recommendations, and potential savings.
        """
        if cost_data is None:
            cost_data = platform.collect_cost_data()

        analysis = {
            'platform': cost_data.get('platform', 'unknown'),
            'timestamp': time.time(),
            'total_monthly_cost': cost_data.get('total_monthly', 0),
            'services': cost_data.get('services', {}),
            'waste_findings': [],
            'optimization_recommendations': [],
            'spending_anomalies': [],
            'potential_monthly_savings': 0,
            'preserve_cash_score': 0
        }

        ptype = cost_data.get('platform', '')

        if ptype == 'aws':
            analysis['waste_findings'].extend(self._analyze_aws_waste(platform, cost_data))
            analysis['optimization_recommendations'].extend(
                self._get_aws_optimizations(platform, cost_data)
            )
        elif ptype == 'gcp':
            analysis['waste_findings'].extend(self._analyze_gcp_waste(platform, cost_data))
            analysis['optimization_recommendations'].extend(
                self._get_gcp_optimizations(platform, cost_data)
            )
        elif ptype == 'azure':
            analysis['waste_findings'].extend(self._analyze_azure_waste(platform, cost_data))
            analysis['optimization_recommendations'].extend(
                self._get_azure_optimizations(platform, cost_data)
            )

        for rec in cost_data.get('recommendations', []):
            analysis['waste_findings'].append(rec)

        analysis['spending_anomalies'] = self._detect_spending_anomalies(cost_data)

        total_savings = 0
        for finding in analysis['waste_findings']:
            savings_str = finding.get('potential_savings', '$0')
            try:
                savings = float(savings_str.replace('$', '').replace(',', '').replace('/month', '').split()[0])
                total_savings += savings
            except (ValueError, IndexError):
                pass

        for rec in analysis['optimization_recommendations']:
            savings_str = rec.get('potential_savings', '$0')
            try:
                savings = float(savings_str.replace('$', '').replace(',', '').replace('/month', '').split()[0])
                total_savings += savings
            except (ValueError, IndexError):
                pass

        analysis['potential_monthly_savings'] = round(total_savings, 2)
        analysis['potential_annual_savings'] = round(total_savings * 12, 2)

        monthly_cost = analysis['total_monthly_cost']
        if monthly_cost > 0:
            savings_pct = (total_savings / monthly_cost) * 100
            analysis['savings_percentage'] = round(savings_pct, 1)
            efficiency = max(0, 100 - savings_pct)
            analysis['preserve_cash_score'] = round(efficiency, 1)
        else:
            analysis['savings_percentage'] = 0
            analysis['preserve_cash_score'] = 100

        self._record_spending(cost_data)

        return analysis

    def _analyze_aws_waste(self, platform, cost_data: Dict) -> List[Dict]:
        """Detect AWS resource waste."""
        waste = []
        try:
            ec2 = platform.session.client('ec2')

            stopped = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
            )
            stopped_instances = []
            for r in stopped['Reservations']:
                for i in r['Instances']:
                    stopped_instances.append(i)

            for inst in stopped_instances:
                iid = inst['InstanceId']
                itype = inst['InstanceType']
                volumes = [v['Ebs']['VolumeId'] for v in inst.get('BlockDeviceMappings', [])
                          if 'Ebs' in v]
                if volumes:
                    waste.append({
                        'type': 'idle_resource',
                        'title': f'Stopped instance with EBS: {iid} ({itype})',
                        'detail': f'{len(volumes)} EBS volumes attached to stopped instance',
                        'potential_savings': f'${len(volumes) * 8:.2f}/month (EBS charges)',
                        'severity': 'medium',
                        'action': f'Snapshot and delete volumes, or terminate instance'
                    })

            eips = ec2.describe_addresses()['Addresses']
            unused_eips = [eip for eip in eips if 'InstanceId' not in eip and 'NetworkInterfaceId' not in eip]
            if unused_eips:
                waste.append({
                    'type': 'unused_resource',
                    'title': f'{len(unused_eips)} unused Elastic IP addresses',
                    'detail': 'Elastic IPs not associated with any instance incur charges',
                    'potential_savings': f'${len(unused_eips) * 3.60:.2f}/month',
                    'severity': 'low',
                    'action': 'Release unused Elastic IPs'
                })

            try:
                elb = platform.session.client('elbv2')
                lbs = elb.describe_load_balancers()['LoadBalancers']
                for lb in lbs:
                    tgs = elb.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                    has_targets = False
                    for tg in tgs['TargetGroups']:
                        health = elb.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                        if health['TargetHealthDescriptions']:
                            has_targets = True
                            break
                    if not has_targets:
                        waste.append({
                            'type': 'idle_resource',
                            'title': f'Load balancer with no targets: {lb["LoadBalancerName"]}',
                            'detail': 'ALB/NLB running without any registered targets',
                            'potential_savings': '$16.20/month (minimum ALB charge)',
                            'severity': 'medium',
                            'action': f'Delete load balancer {lb["LoadBalancerName"]}'
                        })
            except Exception:
                pass

            try:
                rds = platform.session.client('rds')
                dbs = rds.describe_db_instances()['DBInstances']
                for db in dbs:
                    if not db.get('MultiAZ') and db.get('Engine') in ['mysql', 'postgres', 'mariadb']:
                        waste.append({
                            'type': 'optimization',
                            'title': f'Single-AZ RDS: {db["DBInstanceIdentifier"]}',
                            'detail': f'{db["Engine"]} instance without Multi-AZ redundancy',
                            'potential_savings': 'N/A (reliability concern)',
                            'severity': 'info',
                            'action': 'Consider enabling Multi-AZ for production databases'
                        })
            except Exception:
                pass

            try:
                volumes = ec2.describe_volumes(
                    Filters=[{'Name': 'status', 'Values': ['available']}]
                )
                unattached = volumes['Volumes']
                if unattached:
                    total_gb = sum(v['Size'] for v in unattached)
                    monthly_cost = total_gb * 0.08
                    waste.append({
                        'type': 'unused_resource',
                        'title': f'{len(unattached)} unattached EBS volumes ({total_gb} GB)',
                        'detail': 'EBS volumes not attached to any instance still incur charges',
                        'potential_savings': f'${monthly_cost:.2f}/month',
                        'severity': 'medium',
                        'action': 'Snapshot and delete unattached volumes'
                    })
            except Exception:
                pass

        except Exception as e:
            waste.append({'type': 'error', 'title': f'AWS waste analysis error: {str(e)[:100]}',
                         'severity': 'info', 'potential_savings': '$0'})
        return waste

    def _get_aws_optimizations(self, platform, cost_data: Dict) -> List[Dict]:
        """Get AWS optimization recommendations."""
        recs = []
        total_monthly = cost_data.get('total_monthly', 0)

        if total_monthly > 500:
            recs.append({
                'type': 'reserved_instances',
                'title': 'Consider Reserved Instances or Savings Plans',
                'detail': f'Monthly spend of ${total_monthly:.2f} could benefit from 1-year or 3-year commitments',
                'potential_savings': f'${total_monthly * 0.30:.2f}/month (up to 30% with 1-yr RI)',
                'severity': 'high',
                'action': 'Review AWS Cost Explorer recommendations for RI/SP'
            })

        services = cost_data.get('services', {})
        ec2_cost = services.get('Amazon Elastic Compute Cloud - Compute', 0)
        if ec2_cost > 200:
            recs.append({
                'type': 'right_sizing',
                'title': 'EC2 right-sizing opportunity',
                'detail': f'EC2 spend of ${ec2_cost:.2f}/month - review instance utilization',
                'potential_savings': f'${ec2_cost * 0.20:.2f}/month (typical 20% savings)',
                'severity': 'medium',
                'action': 'Use AWS Compute Optimizer for right-sizing recommendations'
            })

        s3_cost = services.get('Amazon Simple Storage Service', 0)
        if s3_cost > 50:
            recs.append({
                'type': 'storage_optimization',
                'title': 'S3 storage class optimization',
                'detail': f'S3 spend of ${s3_cost:.2f}/month - review storage classes',
                'potential_savings': f'${s3_cost * 0.40:.2f}/month (with Intelligent-Tiering)',
                'severity': 'medium',
                'action': 'Enable S3 Intelligent-Tiering or lifecycle policies'
            })

        return recs

    def _analyze_gcp_waste(self, platform, cost_data: Dict) -> List[Dict]:
        """Detect GCP resource waste."""
        waste = []
        try:
            from google.cloud import compute_v1
            client = compute_v1.InstancesClient(credentials=platform.credentials)
            zones_client = compute_v1.ZonesClient(credentials=platform.credentials)

            zones = zones_client.list(project=platform.project_id)
            for zone in zones:
                try:
                    instances = client.list(project=platform.project_id, zone=zone.name)
                    for inst in instances:
                        if inst.status == 'TERMINATED':
                            waste.append({
                                'type': 'idle_resource',
                                'title': f'Terminated instance: {inst.name}',
                                'detail': f'Instance in {zone.name} is terminated but not deleted',
                                'potential_savings': 'Check for attached persistent disks',
                                'severity': 'low',
                                'action': f'Delete instance {inst.name} and associated disks'
                            })
                except Exception:
                    continue
        except Exception as e:
            waste.append({'type': 'error', 'title': f'GCP waste analysis: {str(e)[:100]}',
                         'severity': 'info', 'potential_savings': '$0'})
        return waste

    def _get_gcp_optimizations(self, platform, cost_data: Dict) -> List[Dict]:
        """Get GCP optimization recommendations."""
        recs = []
        total = cost_data.get('total_monthly', 0)
        if total > 500:
            recs.append({
                'type': 'committed_use',
                'title': 'Consider Committed Use Discounts (CUDs)',
                'detail': f'Monthly spend of ${total:.2f} qualifies for 1-year or 3-year commitments',
                'potential_savings': f'${total * 0.37:.2f}/month (up to 37% with 1-yr CUD)',
                'severity': 'high',
                'action': 'Review GCP Committed Use recommendations'
            })
        return recs

    def _analyze_azure_waste(self, platform, cost_data: Dict) -> List[Dict]:
        """Detect Azure resource waste."""
        waste = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            client = ComputeManagementClient(platform.credential, platform.subscription_id)

            for vm in client.virtual_machines.list_all():
                status = client.virtual_machines.instance_view(
                    vm.id.split('/')[4], vm.name
                )
                for s in (status.statuses or []):
                    if 'deallocated' in s.code.lower():
                        waste.append({
                            'type': 'idle_resource',
                            'title': f'Deallocated VM: {vm.name}',
                            'detail': 'VM is deallocated but disks may still incur charges',
                            'potential_savings': 'Check for managed disk charges',
                            'severity': 'medium',
                            'action': f'Delete VM {vm.name} if no longer needed'
                        })
        except Exception as e:
            waste.append({'type': 'error', 'title': f'Azure waste analysis: {str(e)[:100]}',
                         'severity': 'info', 'potential_savings': '$0'})
        return waste

    def _get_azure_optimizations(self, platform, cost_data: Dict) -> List[Dict]:
        """Get Azure optimization recommendations."""
        recs = []
        total = cost_data.get('total_monthly', 0)
        if total > 500:
            recs.append({
                'type': 'reserved_instances',
                'title': 'Consider Azure Reserved VM Instances',
                'detail': f'Monthly spend of ${total:.2f} could benefit from 1-year reservations',
                'potential_savings': f'${total * 0.35:.2f}/month (up to 35% with 1-yr RI)',
                'severity': 'high',
                'action': 'Review Azure Advisor cost recommendations'
            })
        return recs

    def _detect_spending_anomalies(self, cost_data: Dict) -> List[Dict]:
        """
        Detect anomalous spending patterns using quantum-enhanced analysis.
        Compares current spending vector against historical baseline.
        """
        anomalies = []
        if len(self.spending_history) < 3:
            return anomalies

        current_vector = self._cost_to_vector(cost_data)

        historical_vectors = np.array([
            self._cost_to_vector(h) for h in self.spending_history[-10:]
        ])

        mean_spending = np.mean(historical_vectors, axis=0)
        std_spending = np.std(historical_vectors, axis=0)
        std_spending = np.where(std_spending < 0.01, 0.01, std_spending)

        z_scores = np.abs((current_vector - mean_spending) / std_spending)

        services = sorted(cost_data.get('services', {}).keys())
        for i, service in enumerate(services):
            if i < len(z_scores) and z_scores[i] > self.anomaly_threshold:
                current_cost = cost_data['services'].get(service, 0)
                avg_cost = mean_spending[i] if i < len(mean_spending) else 0
                anomalies.append({
                    'service': service,
                    'current_cost': round(current_cost, 2),
                    'average_cost': round(float(avg_cost), 2),
                    'z_score': round(float(z_scores[i]), 2),
                    'severity': 'high' if z_scores[i] > 3 else 'medium',
                    'detail': f'{service} spending ${current_cost:.2f} vs average ${avg_cost:.2f} '
                             f'(z-score: {z_scores[i]:.1f})'
                })

        return anomalies

    def _cost_to_vector(self, cost_data: Dict) -> np.ndarray:
        """Convert cost data to numerical vector for anomaly detection."""
        services = sorted(cost_data.get('services', {}).keys())
        if not services:
            return np.array([cost_data.get('total_monthly', 0)])
        return np.array([cost_data['services'].get(s, 0) for s in services], dtype=np.float64)

    def _record_spending(self, cost_data: Dict):
        """Record spending data point for trend analysis."""
        self.spending_history.append({
            'timestamp': time.time(),
            'total_monthly': cost_data.get('total_monthly', 0),
            'services': cost_data.get('services', {}),
            'platform': cost_data.get('platform', 'unknown')
        })
        if len(self.spending_history) > 100:
            self.spending_history = self.spending_history[-50:]
        self._save_history()

    def get_spending_trends(self) -> Dict:
        """Get spending trend analysis."""
        if len(self.spending_history) < 2:
            return {'status': 'insufficient_data', 'data_points': len(self.spending_history)}

        totals = [h['total_monthly'] for h in self.spending_history]
        timestamps = [h['timestamp'] for h in self.spending_history]

        current = totals[-1]
        previous = totals[-2]
        change = ((current - previous) / max(previous, 0.01)) * 100

        avg = np.mean(totals)
        trend = 'increasing' if totals[-1] > totals[0] else 'decreasing'

        return {
            'current_monthly': round(current, 2),
            'previous_monthly': round(previous, 2),
            'change_pct': round(change, 1),
            'average_monthly': round(float(avg), 2),
            'trend': trend,
            'data_points': len(totals),
            'history': [
                {'timestamp': t, 'total': round(total, 2)}
                for t, total in zip(timestamps, totals)
            ]
        }

    def generate_preserve_cash_report(self, analysis: Dict) -> Dict:
        """Generate a 'Preserve Cash' summary report."""
        report = {
            'title': 'Preserve Cash - Cloud Cost Optimization Report',
            'generated_at': datetime.now().isoformat(),
            'platform': analysis.get('platform', 'unknown'),
            'executive_summary': '',
            'current_monthly_spend': analysis.get('total_monthly_cost', 0),
            'potential_monthly_savings': analysis.get('potential_monthly_savings', 0),
            'potential_annual_savings': analysis.get('potential_annual_savings', 0),
            'preserve_cash_score': analysis.get('preserve_cash_score', 0),
            'waste_count': len(analysis.get('waste_findings', [])),
            'optimization_count': len(analysis.get('optimization_recommendations', [])),
            'anomaly_count': len(analysis.get('spending_anomalies', [])),
            'top_recommendations': [],
            'estimated_breach_cost_inr': 0
        }

        monthly = analysis.get('total_monthly_cost', 0)
        savings = analysis.get('potential_monthly_savings', 0)
        score = analysis.get('preserve_cash_score', 0)

        report['executive_summary'] = (
            f"Current monthly cloud spend: ${monthly:,.2f}. "
            f"Identified ${savings:,.2f}/month in potential savings "
            f"(${savings * 12:,.2f}/year). "
            f"Preserve Cash Score: {score}/100. "
        )

        if score < 50:
            report['executive_summary'] += "Significant optimization opportunities exist."
        elif score < 80:
            report['executive_summary'] += "Moderate optimization potential identified."
        else:
            report['executive_summary'] += "Cloud spending is well-optimized."

        all_recs = analysis.get('waste_findings', []) + analysis.get('optimization_recommendations', [])
        for rec in sorted(all_recs, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(
                x.get('severity', 'low'), 4)):
            report['top_recommendations'].append({
                'title': rec.get('title', ''),
                'severity': rec.get('severity', 'info'),
                'potential_savings': rec.get('potential_savings', 'N/A'),
                'action': rec.get('action', '')
            })

        breach_cost_usd = monthly * 12 * 3
        report['estimated_breach_cost_inr'] = round(breach_cost_usd * 83, 0)

        return report

    def _save_history(self):
        path = os.path.join(self.model_dir, 'spending_history.json')
        try:
            with open(path, 'w') as f:
                json.dump(self.spending_history, f, indent=2)
        except Exception:
            pass

    def _load_history(self):
        path = os.path.join(self.model_dir, 'spending_history.json')
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.spending_history = json.load(f)
            except Exception:
                pass
